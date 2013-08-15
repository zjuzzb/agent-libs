#ifndef _WIN32
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#endif
#include "sinsp.h"
#include "sinsp_int.h"

static void copy_ipv6_address(uint32_t* src, uint32_t* dest)
{
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

sinsp_threadinfo::sinsp_threadinfo() :
	m_transaction_manager(NULL),
	m_fdtable(NULL)
{
	m_pid = (uint64_t) - 1LL;
	set_lastevent_data_validity(false);
	m_lastevent_type = -1;
	m_lastevent_ts = 0;
	m_lastaccess_ts = 0;
	m_lastevent_category = EC_UNKNOWN;
	m_analysis_flags = AF_PARTIAL_METRIC;
	m_flags = 0;
	m_n_threads = 0;
	m_refcount = 0;
}

sinsp_threadinfo::sinsp_threadinfo(sinsp *inspector) :
	m_transaction_manager(inspector),
	m_fdtable(inspector)
{
	m_inspector = inspector;
	m_pid = (uint64_t) - 1LL;
	set_lastevent_data_validity(false);
	m_analysis_flags = AF_PARTIAL_METRIC;
	m_lastevent_type = -1;
	m_lastevent_ts = 0;
	m_lastaccess_ts = inspector->m_lastevent_ts;
	m_lastevent_category = EC_UNKNOWN;
	m_flags = 0;
	m_n_threads = 0;
	m_refcount = 0;
}

void sinsp_threadinfo::init(const scap_threadinfo* pi)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;
	sinsp_fdinfo newfdi;

	m_tid = pi->tid;
	m_pid = pi->pid;
	m_comm = pi->comm;
	m_exe = pi->exe;
	set_args(pi->args, pi->args_len);
	set_cwd(pi->cwd, strlen(pi->cwd));
	m_flags = pi->flags;
	m_fdtable.clear();

	HASH_ITER(hh, pi->fdlist, fdi, tfdi)
	{
		bool do_add = true;

		newfdi.m_type = fdi->type;
		newfdi.m_openflags = fdi->flags;
		newfdi.m_type = fdi->type;
		newfdi.reset_flags();
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

sinsp_fdtable *sinsp_threadinfo::get_fd_table()
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

sinsp_transaction_manager* sinsp_threadinfo::get_transaction_manager()
{
	sinsp_threadinfo* root;

	if(m_flags & PPM_CL_CLONE_FILES)
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

	return &(root->m_transaction_manager);
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

/*
void sinsp_threadinfo::push_fdop(sinsp_fdop* op)
{
    if(m_last_fdop.size() >= 10)
    {
        m_last_fdop.pop_front();
    }

    m_last_fdop.push_back(*op);
}
*/

sinsp_thread_manager::sinsp_thread_manager(sinsp* inspector)
{
	m_inspector = inspector;
	m_last_tid = 0;
	m_last_tinfo = NULL;
	m_last_flush_time_ns = 0;

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
	m_inspector->m_stats.m_n_pending_transactions = 0;
	for(threadinfo_map_iterator_t it = m_threadtable.begin(); it != m_threadtable.end(); it++)
	{
		m_inspector->m_stats.m_n_fds += it->second.get_fd_table()->size();
		m_inspector->m_stats.m_n_pending_transactions += it->second.get_transaction_manager()->get_size();
	}
#endif
}