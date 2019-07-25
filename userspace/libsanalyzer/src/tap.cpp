#include "tap.h"

#include <sinsp_int.h>
#include <analyzer.h>
#include <analyzer_thread.h>

#include "connectinfo.h"

#include "tap.pb.h"

namespace {
tap::ConnectionStatus conn_status(uint8_t flags, int errorcode)
{
	switch(flags & ~sinsp_connection::AF_REUSED) {
		case sinsp_connection::AF_PENDING: return tap::ConnectionStatus::PENDING;
		case sinsp_connection::AF_CLOSED: return tap::ConnectionStatus::CLOSED;
		default: return errorcode == 0 ?
			tap::ConnectionStatus::ESTABLISHED:
			tap::ConnectionStatus::FAILED;
	}
}
}

audit_tap::audit_tap(env_hash_config *config, const std::string &machine_id, bool emit_local_connections) :
	m_machine_id(machine_id),
	m_hostname(sinsp_gethostname()),
	m_emit_local_connections(emit_local_connections),
	m_event_batch(new tap::AuditLog),
	m_config(config),
	m_num_envs_sent(0)
{
	clear();
}

void audit_tap::on_exit(uint64_t pid)
{
	if(m_pids.erase(pid))
	{
		auto pb_exit = m_event_batch->add_processexitevents();
		pb_exit->set_pid(pid);
		pb_exit->set_timestamp(sinsp_utils::get_current_time_ns() / 1000000);
	}
}

void audit_tap::emit_connections(sinsp_ipv4_connection_manager* conn_manager, userdb* userdb)
{
	for(auto& it : conn_manager->m_connections)
	{
		if (
			it.first.m_fields.m_sip == 0 &&
			it.first.m_fields.m_sport == 0 &&
			it.first.m_fields.m_dip == 0 &&
			it.first.m_fields.m_dport == 0)
		{
			continue;
		}

		if (!m_emit_local_connections && it.second.m_spid != 0 && it.second.m_dpid != 0)
		{
			continue;
		}

		auto history = it.second.get_state_history();
		bool have_connections = false;
		for(const auto& transition : history)
		{
			auto pb_conn = m_event_batch->add_connectionevents();
			pb_conn->set_clientipv4(htonl(it.first.m_fields.m_sip));
			pb_conn->set_clientport(it.first.m_fields.m_sport);
			pb_conn->set_clientpid(it.second.m_spid);

			pb_conn->set_serveripv4(htonl(it.first.m_fields.m_dip));
			pb_conn->set_serverport(it.first.m_fields.m_dport);
			pb_conn->set_serverpid(it.second.m_dpid);

			pb_conn->set_status(conn_status(transition.state, transition.error_code));
			pb_conn->set_errorcode(transition.error_code);
			pb_conn->set_timestamp(transition.timestamp / 1000000);

			have_connections = true;
		}

		if(have_connections)
		{
			emit_process(it.second.m_sproc.get(), userdb);
			emit_process(it.second.m_dproc.get(), userdb);
		}
	}
}

void audit_tap::emit_pending_envs(sinsp* inspector)
{
	std::unordered_set<uint64_t> still_unsent;

	size_t num_unsent = m_unsent_envs.size();
	if(num_unsent == 0)
	{
		return;
	}

	for(const auto& pid : m_unsent_envs) {
		if(m_num_envs_sent >= m_config->m_envs_per_flush) {
			still_unsent.insert(pid);
			continue;
		}

		auto tinfo = inspector->get_thread(pid);
		if(!tinfo)
		{
			continue;
		}

		if(!emit_environment(nullptr, tinfo))
		{
			still_unsent.insert(pid);
		}
	}

	m_unsent_envs = std::move(still_unsent);

	g_logger.format(sinsp_logger::SEV_INFO, "audit_tap: %d environments still unsent (from %d)", m_unsent_envs.size(), num_unsent);
	if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
	{
		for (auto pid : m_unsent_envs)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Unsent environment for pid %u", pid);
		}
	}
}

void audit_tap::emit_process(sinsp_threadinfo *tinfo, userdb *userdb)
{
	if (tinfo == nullptr)
	{
		return;
	}

	auto inserted = m_pids.insert(tinfo->m_pid);
	if (!inserted.second)
	{
		return;
	}

	auto proc = m_event_batch->add_newprocessevents();
	proc->set_pid(tinfo->m_pid);
	// To get the parent, first go to the main thread (the first thread
	// that was forked), then take the m_ptid which is the process from
	// which this thread was forked.
	proc->set_parentpid(tinfo->get_main_thread()->m_ptid);
	proc->set_name(tinfo->m_comm);
	for(const auto& arg : tinfo->m_args)
	{
		if(arg.empty())
		{
			continue;
		}

		if(arg.size() <= ARG_SIZE_LIMIT)
		{
			proc->add_commandline(arg);
		}
		else
		{
			auto arg_capped = arg.substr(0, ARG_SIZE_LIMIT);
			proc->add_commandline(arg_capped);
		}
	}

	proc->set_containerid(tinfo->m_container_id);
	proc->set_userid(tinfo->m_uid);
	if (userdb)
	{
		proc->set_username(userdb->lookup(tinfo->m_uid));
	}
	if (m_config->m_send_audit_tap)
	{
		emit_environment(proc, tinfo);
	}

	proc->set_timestamp(tinfo->m_clone_ts / 1000000);
}

bool audit_tap::emit_environment(tap::NewProcess *proc, sinsp_threadinfo *tinfo)
{
	auto mt_ainfo = tinfo->m_ainfo->main_thread_ainfo();
	auto env_hash = mt_ainfo->m_env_hash.get_hash();
	if (proc)
	{
		proc->set_envvariableshash(env_hash.data(), env_hash.size());
	}

	auto now = sinsp_utils::get_current_time_ns();

	auto new_env = m_sent_envs.insert({mt_ainfo->m_env_hash, now + m_config->m_env_hash_ttl});
	// new_env.first->first: env_hash
	// new_env.first->second: last sent timestamp
	// new_env.second: if true, insertion took place (first time we're sending this hash)

	if(!new_env.second && new_env.first->second >= now) {
		return true;
	}

	if(++m_num_envs_sent > m_config->m_envs_per_flush) {
		g_logger.format(sinsp_logger::SEV_INFO, "Environment flush limit reached, throttling");
		if(new_env.second) {
			m_sent_envs.erase(new_env.first);
		}
		m_num_envs_sent--;
		m_unsent_envs.insert(tinfo->m_pid);
		return false;
	} else {
		size_t env_bytes_sent = 0;

		auto env = m_event_batch->add_environmentvariables();
		env->set_hash(env_hash.data(), env_hash.size());

		for(const auto& entry : tinfo->get_env()) {
			if(entry.empty() || entry[0] == '=') {
				continue;
			}
			bool blacklisted = false;
			for(const auto& regex : *m_config->m_env_blacklist) {
				if(regex.match(entry)) {
					blacklisted = true;
					break;
				}
			}

			if(blacklisted) {
				continue;
			}

			env_bytes_sent += entry.size() + 1; // 1 for the trailing NUL
			if(env_bytes_sent > m_config->m_max_env_size) {
				break;
			}

			env->add_variables(entry);
		}

		if(env_bytes_sent > m_config->m_max_env_size) {
			g_logger.format(sinsp_logger::SEV_INFO, "Environment of process %lu (%s) too large, truncating to %d bytes (limit is %d)",
					tinfo->m_pid, tinfo->m_comm.c_str(), env_bytes_sent, m_config->m_max_env_size);
			if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
			{
				for(const auto& entry : tinfo->m_env) {
					g_logger.format(sinsp_logger::SEV_DEBUG, "Environment of process %lu (%s): %s",
							tinfo->m_pid, tinfo->m_comm.c_str(), entry.c_str());
				}
			}
		}

		if(!new_env.second) {
			new_env.first->second = now + m_config->m_env_hash_ttl;
		}
	}

	return true;
}

const tap::AuditLog* audit_tap::get_events()
{
	if (m_event_batch->newprocessevents_size() == 0 &&
		m_event_batch->processexitevents_size() == 0 &&
		m_event_batch->connectionevents_size() == 0 &&
		m_event_batch->environmentvariables_size() == 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "No audit tap messages generated");
		return nullptr;
	}
	m_event_batch->set_timestamp(sinsp_utils::get_current_time_ns() / 1000000);
	return m_event_batch;
}

void audit_tap::clear()
{
	m_event_batch->Clear();
	m_event_batch->set_hostmac(m_machine_id);
	m_event_batch->set_hostname(m_hostname);
	m_num_envs_sent = 0;
}