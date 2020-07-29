#include "analyzer.h"
#include "analyzer_thread.h"
#include "audit_tap.h"
#include "common_logger.h"
#include "connectinfo.h"
#include "sinsp_int.h"
#include "tap.pb.h"
#include "type_config.h"

#include <Poco/File.h>
#include <google/protobuf/util/json_util.h>

#include <fstream>
#include <sstream>

namespace
{
COMMON_LOGGER();

type_config<unsigned int>::ptr c_max_argument_length =
    type_config_builder<unsigned int>(
        100 /*default*/,
        "The maximum length to send for arguments to the command line",
        "audit_tap",
        "max_command_arg_length")
        .min(10)
        .max(64 * 1024)
        .build();

type_config<std::string>::ptr c_protobuf_dir =
    type_config_builder<std::string>(
        "",
        "Full path of the directory into which the agent will write JSON "
        "representations of each audit tap protobufs",
        "audit_tap",
        "metricsfile")
        .hidden()
        .post_init([](type_config<std::string>& config) {
	        // Create the directory if it doesn't exist
	        if (config.get_value() != "")
	        {
		        Poco::File dir(config.get_value());
		        dir.createDirectories();
	        }
        })
        .build();

void write_to_file(const tap::AuditLog& tap)
{
	if (c_protobuf_dir->get_value().empty())
	{
		return;
	}

	std::stringstream out;

	out << "tap_" << tap.timestamp() << ".json";

	const std::string filename = out.str();
	std::ofstream out_file(c_protobuf_dir->get_value() + "/" + filename);

	if (!out_file)
	{
		LOG_INFO("Unable to create protobuf file: %s",
		         (c_protobuf_dir->get_value() + "/" + filename).c_str());
		return;
	}

	std::string json_string;

	::google::protobuf::util::MessageToJsonString(tap, &json_string);

	out_file << json_string;

	const std::string symbolic_link = c_protobuf_dir->get_value() + "/tap_latest.json";
	unlink(symbolic_link.c_str());
	symlink(filename.c_str(), symbolic_link.c_str());
}

tap::ConnectionStatus conn_status(const uint8_t flags, const int errorcode)
{
	if (flags & sinsp_connection::AF_PENDING)
	{
		return tap::ConnectionStatus::PENDING;
	}
	else if (flags & sinsp_connection::AF_CLOSED)
	{
		return tap::ConnectionStatus::CLOSED;
	}
	else
	{
		return errorcode == 0 ? tap::ConnectionStatus::ESTABLISHED : tap::ConnectionStatus::FAILED;
	}
}

} // end namespace



audit_tap::audit_tap(env_hash_config *config, const std::string &machine_id, bool emit_local_connections) :
	m_machine_id(machine_id),
	m_hostname(sinsp_gethostname()),
	m_emit_local_connections(emit_local_connections),
	m_event_batch(new tap::AuditLog),
	m_config(config),
	m_num_envs_sent(0),
	m_connection_aggregator(sinsp_utils::get_current_time_ns)
{
	clear();
}

audit_tap::~audit_tap()
{
	delete m_event_batch;
}

void audit_tap::on_exit(uint64_t pid)
{
	if (m_pids.erase(pid))
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
		const ipv4tuple& iptuple = it.first;
		sinsp_connection& connection = it.second;

		if (iptuple.m_fields.m_sip == 0 && iptuple.m_fields.m_sport == 0 &&
		    iptuple.m_fields.m_dip == 0 && iptuple.m_fields.m_dport == 0)
		{
			continue;
		}

		if (!m_emit_local_connections && connection.m_spid != 0 && connection.m_dpid != 0)
		{
			continue;
		}

		auto history = connection.get_state_history();
		bool have_connections = false;

		for (const auto& transition : history)
		{
			auto status = conn_status(transition.state, transition.error_code);
			auto pb_conn = m_event_batch->add_connectionevents();

			pb_conn->set_clientipv4(htonl(iptuple.m_fields.m_sip));
			pb_conn->set_clientport(iptuple.m_fields.m_sport);
			pb_conn->set_clientpid(connection.m_spid);

			pb_conn->set_serveripv4(htonl(iptuple.m_fields.m_dip));
			pb_conn->set_serverport(iptuple.m_fields.m_dport);
			pb_conn->set_serverpid(connection.m_dpid);

			pb_conn->set_status(status);
			pb_conn->set_errorcode(transition.error_code);
			pb_conn->set_timestamp(transition.timestamp / 1000000);

			have_connections = true;
		}

		if (have_connections)
		{
			emit_process(dynamic_cast<thread_analyzer_info*>(connection.m_sproc.get()), userdb);
			emit_process(dynamic_cast<thread_analyzer_info*>(connection.m_dproc.get()), userdb);
		}

		m_connection_aggregator.update_connection_info(iptuple,
		                                               connection);
	}

	m_connection_aggregator.emit_on_schedule(
			*m_event_batch->mutable_connectionaudit());
}

void audit_tap::emit_network_audit(tap::ConnectionAudit* const conn_audit,
                                   const ipv4tuple& iptuple,
                                   const sinsp_connection& connection)
{
	if (conn_audit == nullptr)
	{
		LOG_ERROR("Failed to allocate tap::ConnectionAudit");
		return;
	}

	conn_audit->set_connectioncounttotal(conn_audit->connectioncounttotal() + 1);

	auto conn = conn_audit->add_connections();

	conn->set_clientipv4(htonl(iptuple.m_fields.m_sip));
	conn->set_clientport(iptuple.m_fields.m_sport);
	conn->set_clientpid(connection.m_spid);

	conn->set_serveripv4(htonl(iptuple.m_fields.m_dip));
	conn->set_serverport(iptuple.m_fields.m_dport);
	conn->set_serverpid(connection.m_dpid);

	conn->set_errorcount(connection.m_metrics.get_error_count());

	const sinsp_counter_bytes* counters = nullptr;
	if (connection.is_server_only())
	{
		counters = &connection.m_metrics.m_server;
		conn_audit->set_connectioncountin(conn_audit->connectioncountin() + 1);
	}
	else
	{
		counters = &connection.m_metrics.m_client;
		conn_audit->set_connectioncountout(conn_audit->connectioncountout() + 1);
	}

	auto requestCounts = conn->mutable_requestcounts();

	requestCounts->set_in(counters->m_count_in);
	requestCounts->set_out(counters->m_count_out);
	requestCounts->set_total(counters->m_count_in + counters->m_count_out);

	auto byteCounts = conn->mutable_bytecounts();

	byteCounts->set_in(counters->m_bytes_in);
	byteCounts->set_out(counters->m_bytes_out);
	byteCounts->set_total(counters->m_bytes_in + counters->m_bytes_out);
}

void audit_tap::emit_pending_envs(sinsp* inspector)
{
	std::unordered_set<uint64_t> still_unsent;

	size_t num_unsent = m_unsent_envs.size();
	if (num_unsent == 0)
	{
		return;
	}

	for (const auto& pid : m_unsent_envs)
	{
		if (m_num_envs_sent >= m_config->m_envs_per_flush)
		{
			still_unsent.insert(pid);
			continue;
		}

		auto tinfo = dynamic_cast<thread_analyzer_info*>(inspector->get_thread(pid));
		if (!tinfo)
		{
			continue;
		}

		if (!emit_environment(nullptr, tinfo))
		{
			still_unsent.insert(pid);
		}
	}

	m_unsent_envs = std::move(still_unsent);

	g_logger.format(sinsp_logger::SEV_INFO,
	                "audit_tap: %d environments still unsent (from %d)",
	                m_unsent_envs.size(),
	                num_unsent);
	if (g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
	{
		for (auto pid : m_unsent_envs)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Unsent environment for pid %u", pid);
		}
	}
}

void audit_tap::emit_process(thread_analyzer_info* tinfo, userdb* userdb)
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
	proc->set_name(tinfo->m_exe);
	for (const auto& arg : tinfo->m_args)
	{
		if (arg.empty())
		{
			continue;
		}

		if (arg.size() <= max_command_argument_length())
		{
			proc->add_commandline(arg);
		}
		else
		{
			auto arg_capped = arg.substr(0, max_command_argument_length());
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

bool audit_tap::emit_environment(tap::NewProcess* proc, thread_analyzer_info* tinfo)
{
	auto mt_ainfo = tinfo->main_thread_ainfo();
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

	if (!new_env.second && new_env.first->second >= now)
	{
		return true;
	}

	if (++m_num_envs_sent > m_config->m_envs_per_flush)
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Environment flush limit reached, throttling");
		if (new_env.second)
		{
			m_sent_envs.erase(new_env.first);
		}
		m_num_envs_sent--;
		m_unsent_envs.insert(tinfo->m_pid);
		return false;
	}
	else
	{
		size_t env_bytes_sent = 0;

		auto env = m_event_batch->add_environmentvariables();
		env->set_hash(env_hash.data(), env_hash.size());

		for (const auto& entry : tinfo->get_env())
		{
			if (entry.empty() || entry[0] == '=')
			{
				continue;
			}
			bool blacklisted = false;
			for (const auto& regex : *m_config->m_env_blacklist)
			{
				if (regex.match(entry))
				{
					blacklisted = true;
					break;
				}
			}

			if (blacklisted)
			{
				continue;
			}

			env_bytes_sent += entry.size() + 1;  // 1 for the trailing NUL
			if (env_bytes_sent > m_config->m_max_env_size)
			{
				break;
			}

			env->add_variables(entry);
		}

		if (env_bytes_sent > m_config->m_max_env_size)
		{
			g_logger.format(
			    sinsp_logger::SEV_INFO,
			    "Environment of process %lu (%s) too large, truncating to %d bytes (limit is %d)",
			    tinfo->m_pid,
			    tinfo->m_comm.c_str(),
			    env_bytes_sent,
			    m_config->m_max_env_size);
			if (g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
			{
				for (const auto& entry : tinfo->m_env)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
					                "Environment of process %lu (%s): %s",
					                tinfo->m_pid,
					                tinfo->m_comm.c_str(),
					                entry.c_str());
				}
			}
		}

		if (!new_env.second)
		{
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

	write_to_file(*m_event_batch);

	return m_event_batch;
}

void audit_tap::clear()
{
	m_event_batch->Clear();
	m_event_batch->set_hostmac(m_machine_id);
	m_event_batch->set_hostname(m_hostname);
	m_num_envs_sent = 0;
}

// static
unsigned int audit_tap::max_command_argument_length()
{
	return c_max_argument_length->get_value();
}
