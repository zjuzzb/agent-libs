#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif
#include <algorithm>
#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"

static void copy_ipv6_address(uint32_t* src, uint32_t* dest)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_threadinfo implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_threadinfo::sinsp_threadinfo() :
	m_fdtable(NULL)
{
	init();
}

sinsp_threadinfo::sinsp_threadinfo(sinsp *inspector) :
	m_fdtable(inspector)
{
	m_inspector = inspector;
	init();
}

void sinsp_threadinfo::init()
{
	m_pid = (uint64_t) - 1LL;
	set_lastevent_data_validity(false);
	m_lastevent_type = -1;
	m_lastevent_ts = 0;
	m_lastaccess_ts = 0;
	m_lastevent_category.m_category = EC_UNKNOWN;
	m_analysis_flags = AF_PARTIAL_METRIC;
	m_flags = 0;
	m_n_threads = 0;
	m_refcount = 0;
	m_procinfo = NULL;
	m_transaction_processing_delay_ns = 0;
	m_n_active_transactions = 0;
	m_fdlimit = -1;
	m_fd_usage_ratio = 0;
	m_connection_queue_usage_ratio = 0;
	m_old_proc_jiffies = 0;
}

sinsp_threadinfo::~sinsp_threadinfo()
{
	if(m_procinfo)
	{
		delete m_procinfo;
	}
}

void sinsp_threadinfo::fix_sockets_coming_from_proc()
{
	sinsp_fdtable* fdtable = get_fd_table();

	if(fdtable == &m_fdtable)
	{
		unordered_map<int64_t, sinsp_fdinfo>::iterator it;
		vector<uint16_t> serverports;

		//
		// First pass: extract the ports on which this thread is listening
		//
		for(it = m_fdtable.m_fdtable.begin(); it != m_fdtable.m_fdtable.end(); it++)
		{
			if(it->second.m_type == SCAP_FD_IPV4_SERVSOCK)
			{
				serverports.push_back(it->second.m_info.m_ipv4serverinfo.m_port);
			}
		}

		//
		// Second pass: fix the sockets so that they are ordered by client->server
		//
		for(it = m_fdtable.m_fdtable.begin(); it != m_fdtable.m_fdtable.end(); it++)
		{
			if(it->second.m_type == SCAP_FD_IPV4_SOCK)
			{
				if(find(serverports.begin(), 
					serverports.end(), 
					it->second.m_info.m_ipv4info.m_fields.m_sport) != serverports.end())
				{
					uint32_t tip;
					uint16_t tport;

					tip = it->second.m_info.m_ipv4info.m_fields.m_sip;
					tport = it->second.m_info.m_ipv4info.m_fields.m_sport;

					it->second.m_info.m_ipv4info.m_fields.m_sip = it->second.m_info.m_ipv4info.m_fields.m_dip;
					it->second.m_info.m_ipv4info.m_fields.m_dip = tip;
					it->second.m_info.m_ipv4info.m_fields.m_sport = it->second.m_info.m_ipv4info.m_fields.m_dport;
					it->second.m_info.m_ipv4info.m_fields.m_dport = tport;

					it->second.m_name = ipv4tuple_to_string(&it->second.m_info.m_ipv4info);

					it->second.set_role_server();
				}
				else
				{
					it->second.set_role_client();
				}
			}
		}
	}
}

void sinsp_threadinfo::init(const scap_threadinfo* pi)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;
	sinsp_fdinfo newfdi;
	string tcomm(pi->comm);

	m_tid = pi->tid;
	m_pid = pi->pid;

	m_comm = pi->comm;
	if(tcomm == "" || tcomm[tcomm.length() - 1] == '/')
	{
		string ts(pi->exe);

		size_t commbegin = ts.rfind('/');

		if(commbegin != string::npos)
		{
			m_comm = ts.substr(commbegin + 1);
		}
	}

	m_exe = pi->exe;
	set_args(pi->args, pi->args_len);
	set_cwd(pi->cwd, strlen(pi->cwd));
	m_flags = pi->flags;
	m_fdtable.clear();
	m_fdlimit = pi->fdlimit;

	HASH_ITER(hh, pi->fdlist, fdi, tfdi)
	{
		bool do_add = true;

		newfdi.m_type = fdi->type;
		newfdi.m_openflags = fdi->flags;
		newfdi.m_type = fdi->type;
		newfdi.m_flags = sinsp_fdinfo::FLAGS_FROM_PROC;
		newfdi.m_ino = fdi->ino;

		switch(newfdi.m_type)
		{
		case SCAP_FD_IPV4_SOCK:
			newfdi.m_info.m_ipv4info.m_fields.m_sip = fdi->info.ipv4info.sip;
			newfdi.m_info.m_ipv4info.m_fields.m_dip = fdi->info.ipv4info.dip;
			newfdi.m_info.m_ipv4info.m_fields.m_sport = fdi->info.ipv4info.sport;
			newfdi.m_info.m_ipv4info.m_fields.m_dport = fdi->info.ipv4info.dport;
			newfdi.m_info.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv4info.l4proto;
			m_inspector->m_network_interfaces->update_fd(&newfdi);
			newfdi.m_name = ipv4tuple_to_string(&newfdi.m_info.m_ipv4info);
			break;
		case SCAP_FD_IPV4_SERVSOCK:
			newfdi.m_info.m_ipv4serverinfo.m_ip = fdi->info.ipv4serverinfo.ip;
			newfdi.m_info.m_ipv4serverinfo.m_port = fdi->info.ipv4serverinfo.port;
			newfdi.m_info.m_ipv4serverinfo.m_l4proto = fdi->info.ipv4serverinfo.l4proto;
			break;
		case SCAP_FD_IPV6_SOCK:
			copy_ipv6_address(fdi->info.ipv6info.sip, newfdi.m_info.m_ipv6info.m_fields.m_sip);
			copy_ipv6_address(fdi->info.ipv6info.dip, newfdi.m_info.m_ipv6info.m_fields.m_dip);
			newfdi.m_info.m_ipv6info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi.m_info.m_ipv6info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi.m_info.m_ipv6info.m_fields.m_l6proto = fdi->info.ipv6info.l6proto;
			newfdi.m_name = ipv6tuple_to_string(&newfdi.m_info.m_ipv6info);
			break;
		case SCAP_FD_IPV6_SERVSOCK:
			copy_ipv6_address(fdi->info.ipv6serverinfo.ip, newfdi.m_info.m_ipv6serverinfo.m_ip);
			newfdi.m_info.m_ipv6serverinfo.m_port = fdi->info.ipv6serverinfo.port;
			newfdi.m_info.m_ipv6serverinfo.m_l6proto = fdi->info.ipv6serverinfo.l6proto;
			//newfdi.m_name = newfi.m_info.m_ipv6serverinfo.to_string();
			break;
		case SCAP_FD_UNIX_SOCK:
			newfdi.m_info.m_unixinfo.m_fields.m_source = fdi->info.unix_socket_info.source;
			newfdi.m_info.m_unixinfo.m_fields.m_dest = fdi->info.unix_socket_info.destination;
			newfdi.m_name = fdi->info.unix_socket_info.fname;
			if(newfdi.m_name.empty())
			{
				newfdi.set_role_client();
			}
			else
			{
				newfdi.set_role_server();
			}
			break;
		case SCAP_FD_FIFO:
		case SCAP_FD_FILE:
		case SCAP_FD_DIRECTORY:
		case SCAP_FD_UNSUPPORTED:
		case SCAP_FD_SIGNALFD:
		case SCAP_FD_EVENTPOLL:
		case SCAP_FD_EVENT:
		case SCAP_FD_INOTIFY:
		case SCAP_FD_TIMERFD:
			newfdi.m_name = fdi->info.fname;
			break;
		default:
			ASSERT(false);
			do_add = false;
			break;
		}

		if(do_add)
		{
			m_fdtable.add(fdi->fd, &newfdi);
		}
	}

	fix_sockets_coming_from_proc();
}

string sinsp_threadinfo::get_comm()
{
	if(m_comm == "python")
	{
		return m_args[0];
	}
	else
	{
		return m_comm;
	}
}

void sinsp_threadinfo::set_args(const char* args, size_t len)
{
	m_args.clear();

	size_t offset = 0;
	while(offset < len)
	{
		m_args.push_back(args + offset);
		offset += m_args.back().length() + 1;
	}
}

bool sinsp_threadinfo::is_main_thread()
{
	return m_tid == m_pid;
}

sinsp_threadinfo* sinsp_threadinfo::get_main_thread()
{
	//
	// Is this a child thread?
	//
	if(m_pid == m_tid)
	{
		//
		// No, this is either a single thread process or the root thread of a
		// multithread process,
		//
		return this;
	}
	else
	{
		//
		// Yes, this is a child thread. Find the process root thread.
		//
		sinsp_threadinfo *ptinfo = m_inspector->get_thread(m_pid, true);
		if(NULL == ptinfo)
		{
			ASSERT(false);
			return NULL;
		}

		return ptinfo;
	}
}

sinsp_fdtable* sinsp_threadinfo::get_fd_table()
{
	sinsp_threadinfo* root;

	if(!(m_flags & PPM_CL_CLONE_FILES))
	{
		root = this;
	}
	else
	{
		root = get_main_thread();
		if(NULL == root)
		{
			ASSERT(false);
			return NULL;
		}
	}

	return &(root->m_fdtable);
}

void sinsp_threadinfo::add_fd(int64_t fd, sinsp_fdinfo *fdinfo)
{
	get_fd_table()->add(fd, fdinfo);
}

void sinsp_threadinfo::remove_fd(int64_t fd)
{
	get_fd_table()->erase(fd);
}

sinsp_fdinfo *sinsp_threadinfo::get_fd(int64_t fd)
{
	if(fd < 0)
	{
		return NULL;
	}

	sinsp_fdtable* fdt = get_fd_table();

	if(fdt)
	{
		return fdt->find(fd);
	}
	else
	{
		ASSERT(false);
	}

	return NULL;
}

void sinsp_threadinfo::store_event(sinsp_evt *evt)
{
	uint32_t elen;

	//
	// Make sure the event data is going to fit
	//
	elen = scap_event_getlen(evt->m_pevt);

	if(elen > SP_EVT_BUF_SIZE)
	{
		ASSERT(false);
		return;
	}

	//
	// Copy the data
	//
	memcpy(m_lastevent_data, evt->m_pevt, elen);
	m_lastevent_cpuid = evt->get_cpuid();
}

bool sinsp_threadinfo::is_lastevent_data_valid()
{
	return (m_lastevent_cpuid != (uint16_t) - 1);
}

void sinsp_threadinfo::set_lastevent_data_validity(bool isvalid)
{
	if(isvalid)
	{
		m_lastevent_cpuid = (uint16_t)1;
	}
	else
	{
		m_lastevent_cpuid = (uint16_t) - 1;
	}
}

sinsp_threadinfo* sinsp_threadinfo::get_cwd_root()
{
	if(!(m_flags & PPM_CL_CLONE_FS))
	{
		return this;
	}
	else
	{
		return  get_main_thread();
	}
}

string sinsp_threadinfo::get_cwd()
{
	sinsp_threadinfo* tinfo = get_cwd_root();

	if(tinfo)
	{
		return tinfo->m_cwd;
	}
	else
	{
		ASSERT(false);
		return "./";
	}
}

void sinsp_threadinfo::set_cwd(const char* cwd, uint32_t cwdlen)
{
	char tpath[SCAP_MAX_PATH_SIZE];
	sinsp_threadinfo* tinfo = get_cwd_root();

	if(tinfo)
	{
		sinsp_utils::concatenate_paths(tpath, 
			SCAP_MAX_PATH_SIZE, 
			(char*)tinfo->m_cwd.c_str(), 
			tinfo->m_cwd.size(), 
			cwd, 
			cwdlen);

		tinfo->m_cwd = tpath;

		if(tinfo->m_cwd[tinfo->m_cwd.size() - 1] != '/')
		{
			tinfo->m_cwd += '/';
		}
	}
	else
	{
		ASSERT(false);
	}
}

void sinsp_threadinfo::print_on(FILE* f)
{
	sinsp_threadinfo* pi = get_main_thread();
	fprintf(f,"tid:%" PRIu64 " pid:%" PRIu64 " ", m_tid, m_pid);
	if(NULL == pi)
	{
		return;
	}
	sinsp_fdtable* fdtable = get_fd_table();
	fprintf(f,"%" PRIu64 " ", (uint64_t)fdtable->size());
	fdtable->print_on(f);
	fprintf(f,"\n");
}

const sinsp_counters* sinsp_threadinfo::get_metrics()
{
	return (const sinsp_counters*)&m_metrics;
}

void sinsp_threadinfo::add_all_metrics(sinsp_threadinfo* other)
{
	if(m_procinfo == NULL)
	{
		m_procinfo = new sinsp_procinfo();
		m_procinfo->clear();
	}

	m_procinfo->m_proc_metrics.add(&other->m_metrics);
	m_procinfo->m_proc_transaction_metrics.add(&other->m_transaction_metrics);
	m_procinfo->m_proc_transaction_processing_delay_ns += other->m_transaction_processing_delay_ns;

	if(other->m_fd_usage_ratio > m_procinfo->m_fd_usage_ratio)
	{
		m_procinfo->m_fd_usage_ratio = other->m_fd_usage_ratio;
	}

	if(other->m_connection_queue_usage_ratio > m_procinfo->m_connection_queue_usage_ratio)
	{
		m_procinfo->m_connection_queue_usage_ratio = other->m_connection_queue_usage_ratio;
	}
}

void sinsp_threadinfo::clear_all_metrics()
{
	if(m_procinfo != NULL)
	{
		ASSERT(is_main_thread());
		m_procinfo->clear();
	}

	m_metrics.clear();
	m_transaction_metrics.clear();
	m_transaction_processing_delay_ns = 0;
	m_fd_usage_ratio = 0;
	m_connection_queue_usage_ratio = 0;
}

//
// Emit all the transactions that are in 
//
void sinsp_threadinfo::flush_inactive_transactions(uint64_t sample_end_time, uint64_t sample_duration)
{
	sinsp_fdtable* fdtable = get_fd_table();

	if(fdtable == &m_fdtable)
	{
		unordered_map<int64_t, sinsp_fdinfo>::iterator it;

		for(it = m_fdtable.m_fdtable.begin(); it != m_fdtable.m_fdtable.end(); it++)
		{
			uint64_t endtime = sample_end_time;

			if((it->second.is_transaction()) && 
				((it->second.is_role_server() && it->second.m_transaction.m_direction == sinsp_partial_transaction::DIR_OUT) ||
				(it->second.is_role_client() && it->second.m_transaction.m_direction == sinsp_partial_transaction::DIR_IN)))
			{
				if(it->second.m_transaction.m_end_time >= endtime)
				{
					//
					// This happens when the sample-generating event is a read or write on a transaction FD.
					// No big deal, we're sure that this transaction doesn't need to ble flushed yet
					//
					return;
				}

				if(endtime - it->second.m_transaction.m_end_time > TRANSACTION_TIMEOUT_NS)
				{
					sinsp_connection *connection;

					if(it->second.is_ipv4_socket())
					{
						connection = m_inspector->get_connection(it->second.m_info.m_ipv4info, 
							endtime);

						ASSERT(connection || m_inspector->m_ipv4_connections->get_n_drops() != 0);
					}
					else if(it->second.is_unix_socket())
					{
						connection = m_inspector->get_connection(it->second.m_info.m_unixinfo, 
							endtime);

						ASSERT(connection || m_inspector->m_unix_connections->get_n_drops() != 0);
					}
					else
					{
						ASSERT(false);
						return;
					}

					if(connection != NULL)
					{
						sinsp_partial_transaction *trinfo = &(it->second.m_transaction);

						trinfo->update(m_inspector,
							this,
							connection,
							0, 
							0,
							-1,
							sinsp_partial_transaction::DIR_CLOSE, 
							0);

						trinfo->m_incoming_bytes = 0;
						trinfo->m_outgoing_bytes = 0;
					}
				}
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_thread_manager implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_thread_manager::sinsp_thread_manager(sinsp* inspector)
{
	m_inspector = inspector;
	m_last_tid = 0;
	m_last_tinfo = NULL;
	m_last_flush_time_ns = 0;
	m_n_drops = 0;

#ifdef GATHER_INTERNAL_STATS
	m_failed_lookups = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_failed_lookups","Failed thread lookups"));
	m_cached_lookups = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_cached_lookups","Cached thread lookups"));
	m_non_cached_lookups = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_non_cached_lookups","Non cached thread lookups"));
	m_added_threads = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_added","Number of added threads"));
	m_removed_threads = &m_inspector->m_stats.get_metrics_registry().register_counter(internal_metrics::metric_name("thread_removed","Removed threads"));
#endif
}


sinsp_threadinfo* sinsp_thread_manager::get_thread(int64_t tid)
{
	threadinfo_map_iterator_t it;

	//
	// Try looking up in our simple cache
	//
	if(m_last_tinfo && tid == m_last_tid)
	{
#ifdef GATHER_INTERNAL_STATS
		m_cached_lookups->increment();
#endif
		m_last_tinfo->m_lastaccess_ts = m_inspector->m_lastevent_ts;
		return m_last_tinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	it = m_threadtable.find(tid);
	
	if(it != m_threadtable.end())
	{
#ifdef GATHER_INTERNAL_STATS
		m_non_cached_lookups->increment();
#endif
		m_last_tid = tid;
		m_last_tinfo = &(it->second);
		m_last_tinfo->m_lastaccess_ts = m_inspector->m_lastevent_ts;
		return &(it->second);
	}
	else
	{
#ifdef GATHER_INTERNAL_STATS
		m_failed_lookups->increment();
#endif
		return NULL;
	}
}

void sinsp_thread_manager::add_thread(const sinsp_threadinfo& threadinfo)
{
#ifdef GATHER_INTERNAL_STATS
	m_added_threads->increment();
#endif

	if(m_threadtable.size() >= m_inspector->m_configuration.get_max_thread_table_size())
	{
		m_n_drops++;
		return;
	}

	m_threadtable[threadinfo.m_tid] = threadinfo;

	if(threadinfo.m_flags & PPM_CL_CLONE_THREAD)
	{
		//
		// Increment the refcount of the main thread so it won't
		// be deleted (if it calls pthread_exit()) until we are done
		//
		ASSERT(threadinfo.m_pid != threadinfo.m_tid);
		sinsp_threadinfo* main_thread = m_inspector->get_thread(threadinfo.m_pid, false);
		if(main_thread)
		{
			++main_thread->m_refcount;
		}
		else
		{
			ASSERT(false);
		}
	}
}

void sinsp_thread_manager::remove_thread(int64_t tid)
{
	remove_thread(m_threadtable.find(tid));
}

void sinsp_thread_manager::remove_thread(threadinfo_map_iterator_t it)
{
	if(it == m_threadtable.end())
	{
		//
		// Looks like there's no thread to remove.
		// Either the thread creation event was dropped or our logic doesn't support the
		// call that created this thread. The assertion will detect it, while in release mode we just
		// keep going.
		//
//		ASSERT(false);
#ifdef GATHER_INTERNAL_STATS
		m_failed_lookups->increment();
#endif
		return;
	}
	else if(it->second.m_refcount == 0)
	{
		if(it->second.m_flags & PPM_CL_CLONE_THREAD)
		{
			//
			// Decrement the refcount of the main thread because
			// this reference is gone
			//
			ASSERT(it->second.m_pid != it->second.m_tid);
			sinsp_threadinfo* main_thread = m_inspector->get_thread(it->second.m_pid, false);
			if(main_thread)
			{
				ASSERT(main_thread->m_refcount);
				--main_thread->m_refcount;
			}
			else
			{
				ASSERT(false);
			}
		}

		//
		// If this is the main thread of a process, erase all the FDs that the process owns
		//
		if(it->second.m_pid == it->second.m_tid)
		{
			unordered_map<int64_t, sinsp_fdinfo> fdtable = it->second.get_fd_table()->m_fdtable;
			unordered_map<int64_t, sinsp_fdinfo>::iterator fdit;

			erase_fd_params eparams;
			eparams.m_remove_from_table = false;
			eparams.m_inspector = m_inspector;
			eparams.m_tinfo = &(it->second);
			eparams.m_ts = m_inspector->m_lastevent_ts;

			for(fdit = fdtable.begin(); fdit != fdtable.end(); ++fdit)
			{
				eparams.m_fd = fdit->first;
				// The canceled fd should always be deleted immediately, so if it appears
				// here it means we have a problem.
				//
				ASSERT(eparams.m_fd != CANCELED_FD_NUMBER);
				eparams.m_fdinfo = &(fdit->second);

				sinsp_parser::erase_fd(&eparams);
			}
		}

		//
		// Reset the cache
		//
		m_last_tid = 0;
		m_last_tinfo = NULL;

#ifdef GATHER_INTERNAL_STATS
		m_removed_threads->increment();
#endif
		m_threadtable.erase(it);
	}
}

void sinsp_thread_manager::remove_inactive_threads()
{
	if(m_last_flush_time_ns == 0)
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts;
	}

	if(m_inspector->m_lastevent_ts > 
		m_last_flush_time_ns + m_inspector->m_configuration.get_inactive_thread_scan_time_ns())
	{
		m_last_flush_time_ns = m_inspector->m_lastevent_ts;

		for(threadinfo_map_iterator_t it = m_threadtable.begin(); it != m_threadtable.end();)
		{
			if(it->second.m_refcount == 0 &&
				m_inspector->m_lastevent_ts > 
				it->second.m_lastaccess_ts + m_inspector->m_configuration.get_thread_timeout_ns())
			{
				//
				// Reset the cache
				//
				m_last_tid = 0;
				m_last_tinfo = NULL;

				m_removed_threads->increment();
				m_threadtable.erase(it++);
			}
			else
			{
				++it;
			}
		}
	}
}

void sinsp_thread_manager::update_statistics()
{
#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats.m_n_threads = get_thread_count();

	m_inspector->m_stats.m_n_fds = 0;
	for(threadinfo_map_iterator_t it = m_threadtable.begin(); it != m_threadtable.end(); it++)
	{
		m_inspector->m_stats.m_n_fds += it->second.get_fd_table()->size();
	}
#endif
}
