#define __STDC_FORMAT_MACROS

#include "analyzer.h"
#include "analyzer_int.h"
#include "connectinfo.h"
#include "metrics.h"
#include "parsers.h"
#include "sinsp.h"
#include "sinsp_int.h"

#include <cstring>
#include <fcntl.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#undef min
#undef max
#include "analyzer_thread.h"
#include "audit_tap.h"
#include "delays.h"
#include "draios.pb.h"
#include "proc_config.h"
#include "procfs_parser.h"
#include "sched_analyzer.h"
#include "scores.h"
#include "sinsp_errno.h"
#include "common_logger.h"

COMMON_LOGGER();

namespace
{
type_config<uint32_t> c_procfs_scan_interval_s(20, "", "procfs_scan_interval");
}
///////////////////////////////////////////////////////////////////////////////
// sinsp_procinfo implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_procinfo::clear()
{
	m_exclude_from_sample = true;
	m_proc_metrics.clear();
	m_proc_transaction_metrics.clear();
	m_connection_queue_usage_pct = 0;
	m_fd_usage_pct = 0;
	m_syscall_errors.clear();
	m_capacity_score = 0;
	m_cpuload = 0;
	m_vmsize_kb = 0;
	m_vmrss_kb = 0;
	m_vmswap_kb = 0;
	m_pfmajor = 0;
	m_pfminor = 0;
	m_n_transaction_threads = 0;

	std::vector<uint64_t>::iterator it;
	for (it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); it++)
	{
		*it = 0;
	}

	m_program_pids.clear();

	m_external_transaction_metrics.clear();

	m_syscall_errors.clear();

	std::vector<std::vector<sinsp_trlist_entry>>::iterator sts;
	for (sts = m_server_transactions_per_cpu.begin(); sts != m_server_transactions_per_cpu.end();
	     sts++)
	{
		sts->clear();
	}

	for (sts = m_client_transactions_per_cpu.begin(); sts != m_client_transactions_per_cpu.end();
	     sts++)
	{
		sts->clear();
	}

	m_protostate.clear();
	m_files_stat.clear();
	m_devs_stat.clear();
	m_fd_count = 0;
	m_start_count = 0;
	m_proc_count = 0;
	m_threads_count = 0;
}

uint64_t sinsp_procinfo::get_tot_cputime()
{
	uint64_t res = 0;

	std::vector<uint64_t>::iterator it;
	for (it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); it++)
	{
		res += *it;
	}

	return res;
}

void main_thread_analyzer_info::hash_environment(thread_analyzer_info* tinfo,
                                                 const env_hash::regex_list_t& blacklist)
{
	if (!m_env_hash.is_valid())
	{
		m_env_hash.update(tinfo, blacklist);
	}
}

///////////////////////////////////////////////////////////////////////////////
// thread_analyzer_info implementation
///////////////////////////////////////////////////////////////////////////////

thread_analyzer_info::thread_analyzer_info(sinsp* inspector, sinsp_analyzer* analyzer)
    : sinsp_threadinfo(inspector),
      m_inspector(inspector),
      m_analyzer(analyzer),
      m_tap(nullptr),
      m_procinfo(nullptr),
      m_prom_check_found(false),
      m_has_metrics(false),
      m_last_port_scan(time_point_t::min()),
      m_last_procfs_port_scan(time_point_t::min())
{
}

thread_analyzer_info::thread_analyzer_info(sinsp* inspector,
                                           sinsp_analyzer* analyzer,
                                           std::shared_ptr<audit_tap>& audit_tap)
    : sinsp_threadinfo(inspector),
      m_inspector(inspector),
      m_analyzer(analyzer),
      m_tap(audit_tap),
      m_procinfo(nullptr),
      m_prom_check_found(false),
      m_has_metrics(false),
      m_last_port_scan(time_point_t::min()),
      m_last_procfs_port_scan(time_point_t::min())
{
}

thread_analyzer_info::~thread_analyzer_info()
{
	if (m_tap != nullptr && is_main_thread())
	{
		m_tap->on_exit(m_pid);
	}
	if (m_procinfo)
	{
		delete m_procinfo;
	}
	m_procinfo = nullptr;
	m_listening_ports.reset();
}

void thread_analyzer_info::init()
{
	m_th_analysis_flags = AF_PARTIAL_METRIC;
	clear_found_app_checks();
	clear_found_prom_check();
	clear_has_metrics();
	m_procinfo = NULL;
	m_connection_queue_usage_pct = 0;
	m_old_proc_jiffies = -1;
	m_cpuload = 0;
	m_old_pfmajor = 0;
	m_old_pfminor = 0;
	m_last_wait_duration_ns = 0;
	m_last_wait_end_time_ns = 0;
	ASSERT(m_inspector->get_machine_info() != NULL);
	m_syscall_errors.clear();
	m_called_execve = false;
	m_last_cmdline_sync_ns = 0;
}

const std::set<double>& thread_analyzer_info::get_percentiles()
{
	// This works because we're single threaded
	if (!m_percentiles_initialized)
	{
		m_percentiles = m_analyzer->get_configuration_read_only()->get_percentiles();
		// all the threads that belong to a process will share the
		// same percentile store allocated for the main thread

		thread_analyzer_info* main_thread = dynamic_cast<thread_analyzer_info*>(get_main_thread());
		bool share_store = this != main_thread;
		m_metrics.set_percentiles(m_percentiles, share_store ? &(main_thread->m_metrics) : nullptr);
		m_transaction_metrics.set_percentiles(
		    m_percentiles,
		    share_store ? &(main_thread->m_transaction_metrics) : nullptr);
		m_external_transaction_metrics.set_percentiles(
		    m_percentiles,
		    share_store ? &(main_thread->m_external_transaction_metrics) : nullptr);

		m_percentiles_initialized = true;
	}

	return m_percentiles;
}

const sinsp_counters* thread_analyzer_info::get_metrics()
{
	return &m_metrics;
}

void thread_analyzer_info::allocate_procinfo_if_not_present()
{
	if (m_procinfo == NULL)
	{
		m_procinfo = new sinsp_procinfo();

		m_procinfo->m_server_transactions_per_cpu.resize(m_inspector->get_machine_info()->num_cpus);
		m_procinfo->m_client_transactions_per_cpu.resize(m_inspector->get_machine_info()->num_cpus);

		m_procinfo->clear();
		if (get_percentiles().size())
		{
			m_procinfo->m_protostate.set_percentiles(get_percentiles());
			m_procinfo->m_proc_metrics.set_percentiles(get_percentiles());
			m_procinfo->m_proc_transaction_metrics.set_percentiles(get_percentiles());
			m_procinfo->m_external_transaction_metrics.set_percentiles(get_percentiles());
		}
	}
}

void thread_analyzer_info::propagate_flag(flags flags, thread_analyzer_info* other)
{
	if (other->m_th_analysis_flags & flags)
	{
		m_th_analysis_flags |= (other->m_th_analysis_flags & flags);
	}
}

void thread_analyzer_info::propagate_flag_bidirectional(flags flag, thread_analyzer_info* other)
{
	m_th_analysis_flags |= other->m_th_analysis_flags & flag;
	other->m_th_analysis_flags |= m_th_analysis_flags & flag;
}

void thread_analyzer_info::add_all_metrics(thread_analyzer_info* other)
{
	uint32_t j;

	get_percentiles();
	allocate_procinfo_if_not_present();

	sinsp_counter_time ttot;
	other->m_metrics.get_total(&ttot);

	if (ttot.m_count != 0)
	{
		m_procinfo->m_proc_metrics.add(&other->m_metrics);
		m_procinfo->m_proc_transaction_metrics.add(&other->m_transaction_metrics);
	}

	if (other->get_fd_usage_pct() > m_procinfo->m_fd_usage_pct)
	{
		m_procinfo->m_fd_usage_pct = (uint32_t)other->get_fd_usage_pct();
	}

	if (other->m_connection_queue_usage_pct > m_procinfo->m_connection_queue_usage_pct)
	{
		m_procinfo->m_connection_queue_usage_pct = other->m_connection_queue_usage_pct;
	}

	if (other->m_cpuload >= 0)
	{
		m_procinfo->m_cpuload += other->m_cpuload;
	}

	//
	// The memory is just per-process, so we sum it into the parent program
	// just if this is not a child thread
	//
	if (other->is_main_thread())
	{
		m_procinfo->m_vmsize_kb += other->m_vmsize_kb;
		m_procinfo->m_vmrss_kb += other->m_vmrss_kb;
		m_procinfo->m_vmswap_kb += other->m_vmswap_kb;
	}

	m_procinfo->m_pfmajor += (other->m_pfmajor - other->m_old_pfmajor);
	m_procinfo->m_pfminor += (other->m_pfminor - other->m_old_pfminor);

	//
	// Propagate client-server flags
	//
	propagate_flag_bidirectional(
	    (thread_analyzer_info::flags)(thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                  thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
	                                  thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT |
	                                  thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT),
	    other);
	propagate_flag_bidirectional(
	    (thread_analyzer_info::flags)(thread_analyzer_info::AF_IS_UNIX_SERVER |
	                                  thread_analyzer_info::AF_IS_UNIX_CLIENT),
	    other);

	//
	// Propagate the CPU times vector
	//
	uint32_t oc = other->m_cpu_time_ns.size();
	if (oc != 0)
	{
		if (m_procinfo->m_cpu_time_ns.size() != oc)
		{
			ASSERT(m_procinfo->m_cpu_time_ns.size() == 0)
			m_procinfo->m_cpu_time_ns.resize(oc);
		}

		for (uint32_t j = 0; j < oc; j++)
		{
			m_procinfo->m_cpu_time_ns[j] += other->m_cpu_time_ns[j];
		}
	}

	//
	// If we are returning programs to the backend, add the child pid to the
	// m_program_pids list
	//
	m_procinfo->m_program_pids.insert(other->m_pid);
	m_procinfo->m_program_uids.insert(other->m_uid);

	if (other->m_transaction_metrics.get_counter()->m_count_in != 0)
	{
		m_procinfo->m_n_transaction_threads++;
	}

	m_procinfo->m_external_transaction_metrics.add(&other->m_external_transaction_metrics);

	m_procinfo->m_syscall_errors.add(&other->m_syscall_errors);

	if (other->m_main_thread_ainfo)
	{
		ASSERT(other->m_main_thread_ainfo->m_server_transactions_per_cpu.size() ==
		       m_procinfo->m_server_transactions_per_cpu.size());
		for (j = 0; j < m_procinfo->m_server_transactions_per_cpu.size(); j++)
		{
			m_procinfo->m_server_transactions_per_cpu[j].insert(
			    m_procinfo->m_server_transactions_per_cpu[j].end(),
			    other->m_main_thread_ainfo->m_server_transactions_per_cpu[j].begin(),
			    other->m_main_thread_ainfo->m_server_transactions_per_cpu[j].end());
		}

		ASSERT(other->m_main_thread_ainfo->m_client_transactions_per_cpu.size() ==
		       m_procinfo->m_client_transactions_per_cpu.size());
		for (j = 0; j < m_procinfo->m_client_transactions_per_cpu.size(); j++)
		{
			m_procinfo->m_client_transactions_per_cpu[j].insert(
			    m_procinfo->m_client_transactions_per_cpu[j].end(),
			    other->m_main_thread_ainfo->m_client_transactions_per_cpu[j].begin(),
			    other->m_main_thread_ainfo->m_client_transactions_per_cpu[j].end());
		}

		m_procinfo->m_protostate.add(&other->m_main_thread_ainfo->m_protostate);
		m_procinfo->m_files_stat.add(other->m_main_thread_ainfo->m_files_stat);
		m_procinfo->m_devs_stat.add(other->m_main_thread_ainfo->m_devs_stat);
	}

	m_procinfo->m_fd_count += other->get_fd_table()->size();

	if (other->m_called_execve)
	{
		m_procinfo->m_start_count += 1;
	}

	if (other->is_main_thread())
	{
		m_procinfo->m_proc_count++;
	}
	++m_procinfo->m_threads_count;
}

void thread_analyzer_info::clear_all_metrics()
{
	if (m_procinfo != NULL)
	{
		m_procinfo->clear();
	}

	m_metrics.clear();
	m_transaction_metrics.clear();
	m_external_transaction_metrics.clear();
	m_connection_queue_usage_pct = 0;
	m_cpuload = 0;
	m_old_pfmajor = m_pfmajor;
	m_old_pfminor = m_pfminor;

	std::vector<uint64_t>::iterator it;
	for (it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); ++it)
	{
		*it = 0;
	}

	m_syscall_errors.clear();

	if (m_main_thread_ainfo)
	{
		std::vector<std::vector<sinsp_trlist_entry>>::iterator sts;
		for (sts = m_main_thread_ainfo->m_server_transactions_per_cpu.begin();
		     sts != m_main_thread_ainfo->m_server_transactions_per_cpu.end();
		     sts++)
		{
			sts->clear();
		}

		std::vector<std::vector<sinsp_trlist_entry>>::iterator cts;
		for (cts = m_main_thread_ainfo->m_client_transactions_per_cpu.begin();
		     cts != m_main_thread_ainfo->m_client_transactions_per_cpu.end();
		     cts++)
		{
			cts->clear();
		}

		m_main_thread_ainfo->m_protostate.clear();
		m_main_thread_ainfo->m_files_stat.clear();
		m_main_thread_ainfo->m_devs_stat.clear();
	}
	m_called_execve = false;
	clear_found_app_checks();
	clear_found_prom_check();
	clear_has_metrics();
}

void thread_analyzer_info::clear_role_flags()
{
	m_th_analysis_flags &=
	    ~(AF_IS_LOCAL_IPV4_SERVER | AF_IS_REMOTE_IPV4_SERVER | AF_IS_UNIX_SERVER |
	      AF_IS_LOCAL_IPV4_CLIENT | AF_IS_REMOTE_IPV4_CLIENT | AF_IS_UNIX_CLIENT);
}

void thread_analyzer_info::scan_listening_ports(bool scan_procfs) const
{
	time_point_t now = time_point_t::min();

	// If this pid has a lot of open fds, only rescan
	// every RESCAN_PORT_INTERVAL_SECS
	if (m_listening_ports && (get_fd_opencount() >= LISTENING_PORT_SCAN_FDLIMIT))
	{
		now = time_point_t::clock::now();
		auto elapsed_secs =
		    std::chrono::duration_cast<std::chrono::seconds>(now - m_last_port_scan).count();
		if ((m_last_port_scan != time_point_t::min()) && (elapsed_secs < RESCAN_PORT_INTERVAL_SECS))
		{
			return;
		}
	}

	m_listening_ports = make_unique<std::set<uint16_t>>();
	auto fd_table = get_fd_table();
	for (const auto& fd : fd_table->m_table)
	{
		if (fd.second.m_type == SCAP_FD_IPV4_SERVSOCK)
		{
			m_listening_ports->insert(fd.second.m_sockinfo.m_ipv4serverinfo.m_port);
		}
		if (fd.second.m_type == SCAP_FD_IPV6_SERVSOCK)
		{
			m_listening_ports->insert(fd.second.m_sockinfo.m_ipv6serverinfo.m_port);
		}
	}

	m_last_port_scan = time_point_t::clock::now();

	// Only scan procfs every procfs_scan_interval
	if (scan_procfs)
	{
		if (now == time_point_t::min())
			now = time_point_t::clock::now();

		auto elapsed_secs =
		    std::chrono::duration_cast<std::chrono::seconds>(now - m_last_procfs_port_scan).count();
		if ((m_last_procfs_port_scan == time_point_t::min()) ||
		    (elapsed_secs >= c_procfs_scan_interval_s.get_value()))
		{
			int prev_size = m_procfs_found_ports.size();
			m_procfs_found_ports.clear();

			sinsp_procfs_parser::read_process_serverports(m_pid,
			                                              *m_listening_ports,
			                                              m_procfs_found_ports);
			m_last_procfs_port_scan = now;

			if (m_procfs_found_ports.size() != prev_size)
			{
				LOG_INFO("Updated list of listening ports for pid %lu %s. Found %lu new ports: %s",
				         m_pid,
				         m_comm.c_str(),
				         m_procfs_found_ports.size() - prev_size,
				         ports_to_string(m_procfs_found_ports).c_str());
			}
		}
	}

	for (auto port : m_procfs_found_ports)
	{
		m_listening_ports->insert(port);
	}
}

//
// Emit all the transactions that are still inactive after timeout_ns nanoseconds
//
void thread_analyzer_info::flush_inactive_transactions(uint64_t sample_end_time,
                                                       uint64_t timeout_ns,
                                                       bool is_subsampling)
{
	bool has_thread_exited = (m_flags & PPM_CL_CLOSED) != 0;

	for (auto& it : get_fd_table()->m_table)
	{
		auto& fd = it.second;
		uint64_t endtime = sample_end_time;

		if (fd.is_transaction())
		{
			if ((fd.is_role_server() &&
			     fd.get_usrstate()->m_direction == sinsp_partial_transaction::DIR_OUT) ||
			    (fd.is_role_client() &&
			     fd.get_usrstate()->m_direction == sinsp_partial_transaction::DIR_IN))
			{
				if (fd.get_usrstate()->m_end_time >= endtime)
				{
					//
					// This happens when the sample-generating event is a read or write on a
					// transaction FD. No big deal, we're sure that this transaction doesn't
					// need to be flushed yet
					//
					return;
				}

				//
				// Note: if the thread has exited, we don't care about the timeout and we flush
				// the connection
				//       no matter what. We can safely assume it's ended.
				//
				if (has_thread_exited || (endtime - fd.get_usrstate()->m_end_time > timeout_ns))
				{
					sinsp_connection* connection;

					if (fd.is_ipv4_socket())
					{
						connection = m_analyzer->get_connection(fd.m_sockinfo.m_ipv4info, endtime);

						ASSERT(connection || m_analyzer->get_num_dropped_ipv4_connections() != 0);
					}
					else if (fd.is_unix_socket())
					{
						return;
					}
					else
					{
						ASSERT(false);
						return;
					}

					if (connection != NULL)
					{
						sinsp_partial_transaction* trinfo = fd.get_usrstate();

						trinfo->update(m_analyzer,
						               this,
						               &fd,
						               connection,
						               0,
						               0,
						               -1,
						               sinsp_partial_transaction::DIR_CLOSE,
#if _DEBUG
						               NULL,
						               0,
#endif
						               NULL,
						               0,
						               0);

						trinfo->m_bytes_in = 0;
						trinfo->m_bytes_out = 0;
					}
				}
			}

			if (is_subsampling)
			{
				sinsp_partial_transaction* trinfo = fd.get_usrstate();
				trinfo->reset();
			}
		}
	}
}

//
// Helper function to add a server transaction to the process list.
// Makes sure that the process is allocated first.
//
void thread_analyzer_info::add_completed_server_transaction(sinsp_partial_transaction* tr,
                                                            bool isexternal)
{
	sinsp_trlist_entry::flags flags =
	    (isexternal) ? sinsp_trlist_entry::FL_EXTERNAL : sinsp_trlist_entry::FL_NONE;

	main_thread_ainfo()->m_server_transactions_per_cpu[tr->m_cpuid].push_back(
	    sinsp_trlist_entry(tr->m_prev_prev_start_of_transaction_time, tr->m_prev_end_time, flags));
}

const proc_config& thread_analyzer_info::get_proc_config()
{
	static const auto SYSDIG_AGENT_CONF = "SYSDIG_AGENT_CONF";
	if (!m_proc_config)
	{
		// 1. some processes (eg. redis) wipe their env
		// try to grab the env from it up to its parent (within the same container)
		auto conf = get_env(SYSDIG_AGENT_CONF);
		sinsp_threadinfo::visitor_func_t visitor = [&conf, this](sinsp_threadinfo* ptinfo) {
			if (!conf.empty() || ptinfo->m_container_id != m_container_id)
			{
				return false;
			}

			conf = ptinfo->get_env(SYSDIG_AGENT_CONF);
			return true;
		};

		traverse_parent_state(visitor);

		// 2. As last chance, use the Env coming from Docker
		if (conf.empty() && !m_container_id.empty())
		{
			const auto container_info =
			    m_inspector->m_container_manager.get_container(m_container_id);
			if (container_info)
			{
				conf = container_info->m_sysdig_agent_conf;
			}
		}

		if (!conf.empty())
		{
			LOG_DEBUG("Found process %ld with custom conf, SYSDIG_AGENT_CONF=%s",
			          m_pid,
			          conf.c_str());
		}
		m_proc_config = make_unique<proc_config>(conf);
	}
	return *m_proc_config;
}

//
// Helper function to add a client transaction to the process list.
// Makes sure that the process is allocated first.
//
void thread_analyzer_info::add_completed_client_transaction(sinsp_partial_transaction* tr,
                                                            bool isexternal)
{
	sinsp_trlist_entry::flags flags =
	    (isexternal) ? sinsp_trlist_entry::FL_EXTERNAL : sinsp_trlist_entry::FL_NONE;

	main_thread_ainfo()->m_client_transactions_per_cpu[tr->m_cpuid].push_back(
	    sinsp_trlist_entry(tr->m_prev_prev_start_of_transaction_time, tr->m_prev_end_time, flags));
}

bool thread_analyzer_info::found_app_check_by_fnmatch(const std::string& pattern) const
{
#ifndef CYGWING_AGENT
	for (const auto& ac_found : m_app_checks_found)
	{
		if (!fnmatch(pattern.c_str(), ac_found.c_str(), FNM_EXTMATCH))
			return true;
	}
#else
	throw sinsp_exception(
	    "thread_analyzer_info::found_app_check_by_fnmatch not implemented on Windows");
	ASSERT(false);
#endif
	return false;
}

std::string thread_analyzer_info::ports_to_string(const std::set<uint16_t>& ports)
{
	std::string ret;
	for (auto port : ports)
	{
		ret += std::to_string(port) + ", ";
	}
	return ret.substr(0, ret.size() - 2);
}

///////////////////////////////////////////////////////////////////////////////
// Support for thread sorting
///////////////////////////////////////////////////////////////////////////////
bool threadinfo_cmp_cpu(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	ASSERT(src->m_procinfo);
	ASSERT(dst->m_procinfo);

	return (src->m_procinfo->m_cpuload > dst->m_procinfo->m_cpuload);
}

bool threadinfo_cmp_memory(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	ASSERT(src->m_procinfo);
	ASSERT(dst->m_procinfo);

	return (src->m_procinfo->m_vmrss_kb > dst->m_procinfo->m_vmrss_kb);
}

bool threadinfo_cmp_io(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	ASSERT(src->m_procinfo);
	ASSERT(dst->m_procinfo);

	return (src->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() >
	        dst->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes());
}

bool threadinfo_cmp_net(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	ASSERT(src->m_procinfo);
	ASSERT(dst->m_procinfo);

	return (src->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() >
	        dst->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes());
}

bool threadinfo_cmp_transactions(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	ASSERT(src->m_procinfo);
	ASSERT(dst->m_procinfo);

	return (src->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() >
	        dst->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count());
}

bool threadinfo_cmp_evtcnt(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	ASSERT(src->m_procinfo);
	ASSERT(dst->m_procinfo);

	sinsp_counter_time tot;
	src->m_procinfo->m_proc_metrics.get_total(&tot);
	uint64_t srctot = tot.m_count;
	tot.clear();
	dst->m_procinfo->m_proc_metrics.get_total(&tot);
	uint64_t dsttot = tot.m_count;

	return (srctot > dsttot);
}

bool threadinfo_cmp_cpu_cs(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	int is_src_server =
	    (src->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server =
	    (dst->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	double s = src->m_procinfo->m_cpuload * (is_src_server * 1000);
	double d = dst->m_procinfo->m_cpuload * (is_dst_server * 1000);

	return (s > d);
}

bool threadinfo_cmp_memory_cs(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	int is_src_server =
	    (src->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server =
	    (dst->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_procinfo->m_vmrss_kb * (is_src_server * 1000);
	uint64_t d = dst->m_procinfo->m_vmrss_kb * (is_dst_server * 1000);

	return (s > d);
}

bool threadinfo_cmp_io_cs(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	int is_src_server =
	    (src->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server =
	    (dst->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() * (is_src_server * 1000);
	uint64_t d = dst->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() * (is_dst_server * 1000);

	return (s > d);
}

bool threadinfo_cmp_net_cs(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	int is_src_server =
	    (src->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server =
	    (dst->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() * (is_src_server * 1000);
	uint64_t d = dst->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() * (is_dst_server * 1000);

	return (s > d);
}

bool threadinfo_cmp_transactions_cs(thread_analyzer_info* src, thread_analyzer_info* dst)
{
	int is_src_server =
	    (src->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server =
	    (dst->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
	                                 thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() *
	             (is_src_server * 1000);
	uint64_t d = dst->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() *
	             (is_dst_server * 1000);

	return (s > d);
}
