#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#ifdef HAS_ANALYZER
#include "parsers.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"
#include "metrics.h"
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "analyzer_thread.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_procinfo implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_procinfo::clear()
{
	m_exclude_from_sample = false;
	m_proc_metrics.clear();
	m_proc_transaction_metrics.clear();
	m_proc_transaction_processing_delay_ns = 0;
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

	vector<uint64_t>::iterator it;
	for(it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); it++)
	{
		*it = 0;
	}

#ifdef ANALYZER_EMITS_PROGRAMS
	m_program_pids.clear();
#endif

	vector<vector<sinsp_trlist_entry>>::iterator sts;
	for(sts = m_server_transactions_per_cpu.begin(); 
		sts != m_server_transactions_per_cpu.end(); sts++)
	{
		sts->clear();
	}

	vector<vector<sinsp_trlist_entry>>::iterator cts;
	for(cts = m_client_transactions_per_cpu.begin(); 
		cts != m_client_transactions_per_cpu.end(); cts++)
	{
		cts->clear();
	}

	m_external_transaction_metrics.clear();
}

uint64_t sinsp_procinfo::get_tot_cputime()
{
	uint64_t res = 0;

	vector<uint64_t>::iterator it;
	for(it = m_cpu_time_ns.begin(); it != m_cpu_time_ns.end(); it++)
	{
		res += *it;
	}

	return res;
}

///////////////////////////////////////////////////////////////////////////////
// thread_analyzer_info implementation
///////////////////////////////////////////////////////////////////////////////
void thread_analyzer_info::init(sinsp *inspector, sinsp_threadinfo* tinfo)
{
	m_inspector = inspector;
	m_analyzer = inspector->m_analyzer;
	m_tinfo = tinfo;
	m_th_analysis_flags = AF_PARTIAL_METRIC;
	m_procinfo = NULL;
	m_connection_queue_usage_pct = 0;
	m_old_proc_jiffies = -1;
	m_cpuload = 0;
	m_old_pfmajor = 0;
	m_old_pfminor = 0;
	m_last_wait_duration_ns = 0;
	m_last_wait_end_time_ns = 0;
	m_cpu_time_ns = new vector<uint64_t>();
}

void thread_analyzer_info::destroy()
{
	if(m_procinfo)
	{
		delete m_procinfo;
		m_procinfo = NULL;
	}

	delete m_cpu_time_ns;
}

const sinsp_counters* thread_analyzer_info::get_metrics()
{
	return (const sinsp_counters*)&m_metrics;
}

void thread_analyzer_info::allocate_procinfo_if_not_present()
{
	if(m_procinfo == NULL)
	{
		m_procinfo = new sinsp_procinfo();
		m_procinfo->m_server_transactions_per_cpu = vector<vector<sinsp_trlist_entry>>(m_inspector->get_machine_info()->num_cpus);
		m_procinfo->m_client_transactions_per_cpu = vector<vector<sinsp_trlist_entry>>(m_inspector->get_machine_info()->num_cpus);
		m_procinfo->clear();
	}
}

void thread_analyzer_info::propagate_flag(flags flags, thread_analyzer_info* other)
{
	if(other->m_th_analysis_flags & flags)
	{
		m_th_analysis_flags |= (other->m_th_analysis_flags & flags);
	}
}

void thread_analyzer_info::propagate_flag_bidirectional(flags flag, thread_analyzer_info* other)
{
	if(other->m_th_analysis_flags & flag)
	{
		m_th_analysis_flags |= flag;
	}
	else
	{
		if(m_th_analysis_flags & flag)
		{
			other->m_th_analysis_flags |= flag;
		}
	}
}

void thread_analyzer_info::add_all_metrics(thread_analyzer_info* other)
{
	allocate_procinfo_if_not_present();

	sinsp_counter_time ttot;
	other->m_metrics.get_total(&ttot);

	if(ttot.m_count != 0)
	{
		m_procinfo->m_proc_metrics.add(&other->m_metrics);
		m_procinfo->m_proc_transaction_metrics.add(&other->m_transaction_metrics);
	}

	if(other->m_tinfo->get_fd_usage_pct() > m_procinfo->m_fd_usage_pct)
	{
		m_procinfo->m_fd_usage_pct = (uint32_t)other->m_tinfo->get_fd_usage_pct();
	}

	if(other->m_connection_queue_usage_pct > m_procinfo->m_connection_queue_usage_pct)
	{
		m_procinfo->m_connection_queue_usage_pct = other->m_connection_queue_usage_pct;
	}

	m_procinfo->m_cpuload += other->m_cpuload;

	//
	// The memory is just per-process, so we sum it into the parent program
	// just if this is not a child thread
	//
	if(other->m_tinfo->is_main_thread())
	{
		m_procinfo->m_vmsize_kb += other->m_tinfo->m_vmsize_kb;
		m_procinfo->m_vmrss_kb += other->m_tinfo->m_vmrss_kb;
		m_procinfo->m_vmswap_kb += other->m_tinfo->m_vmswap_kb;
	}

	m_procinfo->m_pfmajor += (other->m_tinfo->m_pfmajor - other->m_old_pfmajor);
	m_procinfo->m_pfminor += (other->m_tinfo->m_pfminor - other->m_old_pfminor);

	//
	// Propagate client-server flags
	//
	propagate_flag((thread_analyzer_info::flags)(thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | 
		thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER | 
		thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT | 
		thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT), other);
	propagate_flag((thread_analyzer_info::flags)(thread_analyzer_info::AF_IS_UNIX_SERVER | 
		thread_analyzer_info::AF_IS_UNIX_CLIENT), other);

	//
	// Propagate the CPU times vector
	//
	uint32_t oc = other->m_cpu_time_ns->size();
	if(oc != 0)
	{
		if(m_procinfo->m_cpu_time_ns.size() != oc)
		{
			ASSERT(m_procinfo->m_cpu_time_ns.size() == 0)
			m_procinfo->m_cpu_time_ns.resize(oc);
		}

		for(uint32_t j = 0; j < oc; j++)
		{
			m_procinfo->m_cpu_time_ns[j] += (*other->m_cpu_time_ns)[j];
		}
	}

	//
	// If we are returning programs to the backend, add the child pid to the
	// m_program_pids list
	//
#ifdef ANALYZER_EMITS_PROGRAMS
	ASSERT(other->m_tinfo != NULL);

	if(other->m_tinfo->is_main_thread())
	{
		m_procinfo->m_program_pids.push_back(other->m_tinfo->m_pid);
	}
#endif

	if(other->m_transaction_metrics.get_counter()->m_count_in != 0)
	{
		m_procinfo->m_n_transaction_threads++;
	}

	m_procinfo->m_external_transaction_metrics.add(&other->m_external_transaction_metrics);
}

void thread_analyzer_info::clear_all_metrics()
{
	ASSERT(m_tinfo != NULL);

	if(m_procinfo != NULL)
	{
		ASSERT(m_tinfo->is_main_thread());
		m_procinfo->clear();
	}

	m_metrics.clear();
	m_transaction_metrics.clear();
	m_external_transaction_metrics.clear();
	m_connection_queue_usage_pct = 0;
	m_cpuload = 0;
	m_old_pfmajor = m_tinfo->m_pfmajor;
	m_old_pfminor = m_tinfo->m_pfminor;

	vector<uint64_t>::iterator it;
	for(it = m_cpu_time_ns->begin(); it != m_cpu_time_ns->end(); ++it)
	{
		*it = 0;
	}
}

void thread_analyzer_info::clear_role_flags()
{
	m_th_analysis_flags &= ~(AF_IS_LOCAL_IPV4_SERVER | AF_IS_REMOTE_IPV4_SERVER |
		AF_IS_UNIX_SERVER | AF_IS_LOCAL_IPV4_CLIENT | AF_IS_REMOTE_IPV4_CLIENT | AF_IS_UNIX_CLIENT);
}

//
// Emit all the transactions that are still inactive after timeout_ns nanoseconds
//
void thread_analyzer_info::flush_inactive_transactions(uint64_t sample_end_time, uint64_t timeout_ns, bool is_subsampling)
{
	sinsp_fdtable* fdtable = m_tinfo->get_fd_table();

	if(fdtable == &m_tinfo->m_fdtable)
	{
		unordered_map<int64_t, sinsp_fdinfo_t>::iterator it;

		for(it = m_tinfo->m_fdtable.m_table.begin(); it != m_tinfo->m_fdtable.m_table.end(); it++)
		{
			uint64_t endtime = sample_end_time;

			if(it->second.is_transaction())
			{
				if((it->second.is_role_server() && it->second.m_usrstate.m_direction == sinsp_partial_transaction::DIR_OUT) ||
					(it->second.is_role_client() && it->second.m_usrstate.m_direction == sinsp_partial_transaction::DIR_IN))
				{
					if(it->second.m_usrstate.m_end_time >= endtime)
					{
						//
						// This happens when the sample-generating event is a read or write on a transaction FD.
						// No big deal, we're sure that this transaction doesn't need to be flushed yet
						//
						return;
					}

					if(endtime - it->second.m_usrstate.m_end_time > timeout_ns)
					{
						sinsp_connection *connection;

						if(it->second.is_ipv4_socket())
						{
							connection = m_analyzer->get_connection(it->second.m_sockinfo.m_ipv4info, 
								endtime);

							ASSERT(connection || m_analyzer->m_ipv4_connections->get_n_drops() != 0);
						}
						else if(it->second.is_unix_socket())
						{
#ifdef HAS_UNIX_CONNECTIONS
							connection = m_analyzer->get_connection(it->second.m_sockinfo.m_unixinfo, 
								endtime);

							ASSERT(connection || m_analyzer->m_unix_connections->get_n_drops() != 0);
#else
							return;
#endif
						}
						else
						{
							ASSERT(false);
							return;
						}

						if(connection != NULL)
						{
							sinsp_partial_transaction *trinfo = &(it->second.m_usrstate);

							trinfo->update(m_analyzer,
								m_tinfo,
								&it->second,
								connection,
								0, 
								0,
								-1,
								sinsp_partial_transaction::DIR_CLOSE,
#if _DEBUG
								NULL,
								0,
#endif
								0);

							trinfo->m_incoming_bytes = 0;
							trinfo->m_outgoing_bytes = 0;
						}
					}
				}

				if(is_subsampling)
				{
					sinsp_partial_transaction *trinfo = &(it->second.m_usrstate);
					trinfo->reset();
				}
			}
		}
	}
}

//
// Helper function to add a server transaction to the process list.
// Makes sure that the process is allocated first.
//
void thread_analyzer_info::add_completed_server_transaction(sinsp_partial_transaction* tr, bool isexternal)
{
	allocate_procinfo_if_not_present();

	sinsp_trlist_entry::flags flags = (isexternal)?sinsp_trlist_entry::FL_EXTERNAL : sinsp_trlist_entry::FL_NONE;

	m_procinfo->m_server_transactions_per_cpu[tr->m_cpuid].push_back(
		sinsp_trlist_entry(tr->m_prev_prev_start_of_transaction_time, tr->m_prev_end_time, flags));
}

//
// Helper function to add a client transaction to the process list.
// Makes sure that the process is allocated first.
//
void thread_analyzer_info::add_completed_client_transaction(sinsp_partial_transaction* tr, bool isexternal)
{
	allocate_procinfo_if_not_present();

	sinsp_trlist_entry::flags flags = (isexternal)?sinsp_trlist_entry::FL_EXTERNAL : sinsp_trlist_entry::FL_NONE;

	m_procinfo->m_client_transactions_per_cpu[tr->m_cpuid].push_back(
		sinsp_trlist_entry(tr->m_prev_prev_start_of_transaction_time, 
		tr->m_prev_end_time, flags));
}

bool thread_analyzer_info::is_main_program_thread()
{
	if(m_tinfo->m_progid == -1)
	{
		return m_tinfo->m_tid == m_tinfo->m_pid;
	}
	else
	{
		return false;
	}
}

sinsp_threadinfo* thread_analyzer_info::get_main_program_thread()
{
	if(m_tinfo->m_main_program_thread == NULL)
	{
		//
		// Is this a sub-process?
		//
		if(m_tinfo->m_progid != -1)
		{
			//
			// Yes, this is a child sub-process. Find the program root thread.
			//
			sinsp_threadinfo *ttinfo = m_inspector->get_thread(m_tinfo->m_progid, true, true);
			if(NULL == ttinfo)
			{
				ASSERT(false);
				return NULL;
			}

			sinsp_threadinfo *pptinfo = ttinfo->m_ainfo->get_main_program_thread();
			m_tinfo->m_main_program_thread = pptinfo;
		}
		else
		{
			sinsp_threadinfo *mtinfo;

			//
			// Is this a child thread?
			//
			if(m_tinfo->m_pid == m_tinfo->m_tid)
			{
				//
				// No, this is either a single thread process or the root thread of a
				// multithread process.
				// Note: we don't set m_main_thread because there are cases in which this is 
				//       invoked for a threadinfo that is in the stack. Caching the this pointer
				//       would cause future mess.
				//
				return m_tinfo;
			}
			else
			{
				//
				// Yes, this is a child thread. Find the process root thread.
				//
				mtinfo = m_inspector->get_thread(m_tinfo->m_pid, true, true);
				if(NULL == mtinfo)
				{
					ASSERT(false);
					return NULL;
				}
			}

			sinsp_threadinfo *pptinfo = mtinfo->m_ainfo->get_main_program_thread();
			m_tinfo->m_main_program_thread = pptinfo;
		}
	}

	return m_tinfo->m_main_program_thread;
}

///////////////////////////////////////////////////////////////////////////////
// analyzer_threadtable_listener implementation
///////////////////////////////////////////////////////////////////////////////
analyzer_threadtable_listener::analyzer_threadtable_listener(sinsp* inspector, sinsp_analyzer* analyzer)
{
	m_inspector = inspector; 
	m_analyzer = analyzer;
}

void analyzer_threadtable_listener::on_thread_created(sinsp_threadinfo* tinfo)
{
	void *buffer = tinfo->get_private_state(m_analyzer->m_thread_memory_id);

	//
	// Placement new, see http://www.parashift.com/c++-faq-lite/placement-new.html
	//
	tinfo->m_ainfo = new (buffer) thread_analyzer_info();
	tinfo->m_ainfo->init(m_inspector, tinfo);
}

void analyzer_threadtable_listener::on_thread_destroyed(sinsp_threadinfo* tinfo)
{
	if(tinfo->m_ainfo)
	{
		tinfo->m_ainfo->destroy();
	}
}

///////////////////////////////////////////////////////////////////////////////
// Support for thread sorting
///////////////////////////////////////////////////////////////////////////////
bool threadinfo_cmp_cpu(sinsp_threadinfo* src , sinsp_threadinfo* dst)
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_cpuload > 
		dst->m_ainfo->m_procinfo->m_cpuload); 
}

bool threadinfo_cmp_memory(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_vmrss_kb > 
		dst->m_ainfo->m_procinfo->m_vmrss_kb); 
}

bool threadinfo_cmp_io(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() > 
		dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes()); 
}

bool threadinfo_cmp_net(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 
		dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes()); 
}

bool threadinfo_cmp_transactions(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{
	ASSERT(src->m_ainfo);
	ASSERT(src->m_ainfo->m_procinfo);
	ASSERT(dst->m_ainfo);
	ASSERT(dst->m_ainfo->m_procinfo);

	return (src->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() > 
		dst->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count()); 
}

bool threadinfo_cmp_cpu_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst)
{
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	double s = src->m_ainfo->m_procinfo->m_cpuload * (is_src_server * 1000);
	double d = dst->m_ainfo->m_procinfo->m_cpuload * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_memory_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_vmrss_kb * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_vmrss_kb * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_io_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_net_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{ 
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() * (is_dst_server * 1000);

	return (s > d); 
}

bool threadinfo_cmp_transactions_cs(sinsp_threadinfo* src , sinsp_threadinfo* dst) 
{
	int is_src_server = (src->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));
	int is_dst_server = (dst->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER));

	uint64_t s = src->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() * (is_src_server * 1000);
	uint64_t d = dst->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->get_tot_count() * (is_dst_server * 1000);

	return (s > d); 
}

#endif // HAS_ANALYZER
