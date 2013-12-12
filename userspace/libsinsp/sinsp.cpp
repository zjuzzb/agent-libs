
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <poll.h>
#endif // _WIN32

#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"
#include "metrics.h"
#include "analyzer.h"
#include "filter.h"
#include "filterchecks.h"

//#include "drfilterParser.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp implementation
///////////////////////////////////////////////////////////////////////////////
sinsp::sinsp() :
	m_evt(this)
{
	m_h = NULL;
	m_parser = NULL;
	m_analyzer = NULL;
	m_ipv4_connections = NULL;
	m_unix_connections = NULL;
	m_pipe_connections = NULL;
	m_trans_table = NULL;
	m_dumper = NULL;
	m_network_interfaces = NULL;
#ifdef GATHER_INTERNAL_STATS
	m_stats.clear();
#endif
	m_thread_manager = NULL;
	m_analyzer_callback = NULL;
#ifdef HAS_FILTERING
	m_filter = NULL;
	m_firstevent_ts = 0;
#endif

	m_fds_to_remove = new vector<int64_t>;
	m_machine_info = NULL;
}

sinsp::~sinsp()
{
	close();

	if(m_fds_to_remove)
	{
		delete m_fds_to_remove;
	}
}

void sinsp::open(uint32_t timeout_ms)
{
	char error[SCAP_LASTERR_SIZE];

	g_logger.log("starting live capture");

	m_islive = true;
	m_h = scap_open_live(error);

	if(m_h == NULL)
	{
		throw sinsp_exception(error);
	}

	init();
}

void sinsp::open(string filename)
{
	char error[SCAP_LASTERR_SIZE];

	m_islive = false;

	if(filename == "")
	{
		open();
		return;
	}

	g_logger.log("starting offline capture");

	m_h = scap_open_offline((char *)filename.c_str(), error);

	if(m_h == NULL)
	{
		throw sinsp_exception(error);
	}

	init();
}

void sinsp::close()
{
	if(m_h)
	{
		scap_close(m_h);
		m_h = NULL;
	}

	if(m_parser)
	{
		delete m_parser;
		m_parser = NULL;
	}

	if(m_analyzer)
	{
		delete m_analyzer;
		m_analyzer = NULL;
	}

	if(m_ipv4_connections)
	{
		delete m_ipv4_connections;
		m_ipv4_connections = NULL;
	}

	if(m_unix_connections)
	{
		delete m_unix_connections;
		m_unix_connections = NULL;
	}

	if(m_pipe_connections)
	{
		delete m_pipe_connections;
		m_pipe_connections = NULL;
	}

	if(m_trans_table)
	{
		delete m_trans_table;
		m_trans_table = NULL;
	}

	if(NULL != m_dumper)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}

	if(NULL != m_network_interfaces)
	{
		delete m_network_interfaces;
		m_network_interfaces = NULL;
	}

	if(NULL != m_thread_manager)
	{
		delete m_thread_manager;
		m_thread_manager = NULL;
	}

#ifdef HAS_FILTERING
	if(m_filter != NULL)
	{
		delete m_filter;
	}
#endif
}

void sinsp::start_dump(const string& dump_filename)
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not yet opened");
	}

	m_dumper = scap_dump_open(m_h, dump_filename.c_str());
	if(NULL == m_dumper)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::stop_dump()
{
	if(NULL == m_h)
	{
		throw sinsp_exception("inspector not yet opened");
	}

	if(m_dumper != NULL)
	{
		scap_dump_close(m_dumper);
		m_dumper = NULL;
	}
}

sinsp_configuration* sinsp::get_configuration()
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if(m_h != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("Attempting to set the configuration while the inspector is capturing");
	}

	return &m_configuration;
}

void sinsp::set_configuration(const sinsp_configuration& configuration)
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if(m_h != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("Attempting to set the configuration while the inspector is capturing");
	}

	m_configuration = configuration;
}

void sinsp::import_proc_table()
{
	scap_threadinfo *pi;
	scap_threadinfo *tpi;
	sinsp_threadinfo newpi(this);

	scap_threadinfo *table = scap_get_proc_table(m_h);

	//
	// Scan the scap table and add the threads to our list
	//
	HASH_ITER(hh, table, pi, tpi)
	{
		newpi.init(pi);
		m_thread_manager->add_thread(newpi, true);
	}

	//
	// Scan the list to create the proper parent/child dependencies
	//
	threadinfo_map_iterator_t it;
	for(it = m_thread_manager->m_threadtable.begin(); 
		it != m_thread_manager->m_threadtable.end(); ++it)
	{
		m_thread_manager->increment_mainthread_childcount(&it->second);
		m_thread_manager->increment_program_childcount(&it->second);
	}

	//
	// Scan the list to fix the direction of the sockets
	//
	m_thread_manager->fix_sockets_coming_from_proc();
}

void sinsp::import_ifaddr_list()
{
	m_network_interfaces = new sinsp_network_interfaces;
	m_network_interfaces->import_interfaces(scap_get_ifaddr_list(m_h));
}

void sinsp::import_user_list()
{
	uint32_t j;
	scap_userlist* ul = scap_get_user_list(m_h);

	for(j = 0; j < ul->nusers; j++)
	{
		m_userlist[ul->users[j].uid] = &(ul->users[j]); 
	}

	for(j = 0; j < ul->ngroups; j++)
	{
		m_grouplist[ul->groups[j].gid] = &(ul->groups[j]); 
	}
}

void sinsp::import_ipv4_interface(const sinsp_ipv4_ifinfo& ifinfo)
{
	ASSERT(m_network_interfaces);
	m_network_interfaces->import_ipv4_interface(ifinfo);
}

void sinsp::init()
{
	//
	// Retrieve machine information
	//
	m_machine_info = scap_get_machine_info(m_h);
	if(m_machine_info != NULL)
	{
		m_num_cpus = m_machine_info->num_cpus;
	}
	else
	{
		ASSERT(false);
		m_num_cpus = 0;
	}

	//
	// Allocations
	//
	m_parser = new sinsp_parser(this);
	m_analyzer = new sinsp_analyzer(this);
	if(m_analyzer_callback)
	{
		set_analyzer_callback(m_analyzer_callback);
	}

	m_ipv4_connections = new sinsp_ipv4_connection_manager(this);
	m_unix_connections = new sinsp_unix_connection_manager(this);
	m_pipe_connections = new sinsp_pipe_connection_manager(this);
	m_trans_table = new sinsp_transaction_table(this);
	m_thread_manager = new sinsp_thread_manager(this);

	//
	// Basic inits
	//
	m_tid_to_remove = -1;
	m_lastevent_ts = 0;

	import_ifaddr_list();
	import_proc_table();
	import_user_list();

	//
	// Notify the analyzer that we're starting
	//
	m_analyzer->on_capture_start();
}

void sinsp::remove_expired_connections(uint64_t ts)
{
	m_ipv4_connections->remove_expired_connections(ts);
	m_unix_connections->remove_expired_connections(ts);
}

int32_t sinsp::next(OUT sinsp_evt **evt)
{
	uint32_t j;

	//
	// Get the event from libscap
	//
	int32_t res = scap_next(m_h, &(m_evt.m_pevt), &(m_evt.m_cpuid));
	if(res != SCAP_SUCCESS)
	{
		if(res == SCAP_TIMEOUT)
		{
			return res;
		}
		else if(res == SCAP_EOF)
		{
#ifdef HAS_ANALYZER
			m_analyzer->process_event(NULL);
#endif
		}
		else
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}

		return res;
	}

	//
	// Store a couple of values that we'll need later inside the event.
	//
	m_evt.m_evtnum = get_num_events();
	m_lastevent_ts = m_evt.get_ts();
#ifdef HAS_FILTERING
	if(m_firstevent_ts == 0)
	{
		m_firstevent_ts = m_lastevent_ts;
	}
#endif

#ifndef HAS_ANALYZER
	//
	// Deleayed removal of threads from the thread table, so that
	// things like exit() or close() can be parsed.
	// We only do this if the analyzer is not enabled, because the analyzer
	// needs the process at the end of the sample and will take care of deleting
	// it.
	//
	if(m_tid_to_remove != -1)
	{
		remove_thread(m_tid_to_remove);
		m_tid_to_remove = -1;
	}

	//
	// Run the periodic connection and thread table cleanup
	//
	remove_expired_connections(m_evt.get_ts());
	m_thread_manager->remove_inactive_threads();
#endif

	//
	// Deleayed removal of the fd, so that
	// things like exit() or close() can be parsed.
	//
	uint32_t nfdr = m_fds_to_remove->size();

	if(nfdr != 0)
	{
		sinsp_threadinfo* ptinfo = get_thread(m_tid_of_fd_to_remove, true);
		if(!ptinfo)
		{
			ASSERT(false);
			return res;
		}

		for(j = 0; j < nfdr; j++)
		{
			ptinfo->remove_fd(m_fds_to_remove->at(j));
		}

		m_fds_to_remove->clear();
	}

	//
	// Run the stateful parsing engine
	//
	m_parser->process_event(&m_evt);

#ifdef _DEBUG
	if(m_evt.m_filtered_out)
	{
		return SCAP_TIMEOUT;
	}
#endif

	//
	// If needed, dump the event to file
	//
	if(NULL != m_dumper)
	{
		res = scap_dump(m_h, m_dumper, m_evt.m_pevt, m_evt.m_cpuid);
		if(SCAP_SUCCESS != res)
		{
			throw sinsp_exception(scap_getlasterr(m_h));
		}
	}

	//
	// Run the analysis engine
	//
#ifdef HAS_ANALYZER
	m_analyzer->process_event(&m_evt);
#endif

	// Update the last event time for this thread
	if(m_evt.m_tinfo)
	{
		m_evt.m_tinfo->m_prevevent_ts = m_evt.m_tinfo->m_lastevent_ts;
		m_evt.m_tinfo->m_lastevent_ts = m_lastevent_ts;
	}

	//
	// Done
	//
	*evt = &m_evt;
	return res;
}

uint64_t sinsp::get_num_events()
{
	return scap_event_get_num(m_h);
}

sinsp_threadinfo* sinsp::get_thread(int64_t tid, bool query_os_if_not_found)
{
	sinsp_threadinfo* sinsp_proc = m_thread_manager->get_thread(tid);

	if(sinsp_proc == NULL && query_os_if_not_found)
	{
		sinsp_threadinfo newpi(this);
		scap_threadinfo* scap_proc = scap_proc_get(m_h, tid);

		if(scap_proc)
		{
			newpi.init(scap_proc);
			scap_proc_free(m_h, scap_proc);
		}
		else
		{
			//
			// Add a fake entry to avoid a continuous lookup
			//
			newpi.m_tid = tid;
			newpi.m_pid = tid;
			newpi.m_ptid = -1;
			newpi.m_comm = "<NA>";
			newpi.m_exe = "<NA>";
			newpi.m_uid = 0xffffffff;
			newpi.m_gid = 0xffffffff;
		}

		m_thread_manager->add_thread(newpi);
		sinsp_proc = m_thread_manager->get_thread(tid);
	}

	return sinsp_proc;
}

void sinsp::add_thread(const sinsp_threadinfo& ptinfo)
{
	m_thread_manager->add_thread((sinsp_threadinfo&)ptinfo);
}

void sinsp::remove_thread(int64_t tid)
{
	m_thread_manager->remove_thread(tid);
}

//
// Push an fd operation into the fifo queue for a thread
//
void sinsp::push_fdop(int64_t tid, sinsp_fdinfo *fdinfo, sinsp_fdop &op)
{
	return;
	/*
	    unordered_map<int64_t, sinsp_threadinfo>::iterator it;
	    sinsp_threadinfo* ptinfo;

	    //
	    // Skip events for the moment
	    //
	    if(fdinfo->m_type == SCAP_FD_EVENT)
	    {
	        return;
	    }

	    //
	    // Find the thread info for this tid
	    //
	    it = m_proctable.find(tid);
	    if(it == m_proctable.end())
	    {
	        //
	        // Uh-Oh, can't find the thread. Ignore this event.
	        //
	        ASSERT(false);
	        return;
	    }

	    sinsp_threadinfo& tinfo = it->second;

	    //
	    // Is this a child thread?
	    //
	    if((tinfo.m_pid == tid) || !(tinfo.m_flags & PPM_CL_CLONE_FILES))
	    {
	        //
	        // No, this is either a single thread process or the root thread of a
	        // multithread process, we can add the fd to it
	        //
	        ptinfo = &tinfo;
	    }
	    else
	    {
	        //
	        // Yes, this is a thread. Find the process info for the process root
	        // thread.
	        //
	        it = m_proctable.find(tinfo.m_pid);
	        if(it == m_proctable.end())
	        {
	            //
	            // Uh-Oh, can't find the pid thread. Ignore this event.
	            //
	            ASSERT(false);
	            return;
	        }

	        sinsp_threadinfo& tginfo = it->second;
	        ptinfo = &tginfo;
	    }

	    ptinfo->push_fdop(op);
	*/
}

sinsp_transaction_table *sinsp::get_transactions()
{
	return m_trans_table;
}

void sinsp::stop_capture()
{
	if(scap_stop_capture(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::start_capture()
{
	if(scap_start_capture(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::stop_dropping_mode()
{
	if(scap_stop_dropping_mode(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

void sinsp::start_dropping_mode()
{
	if(scap_start_dropping_mode(m_h) != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

#ifdef _DEBUG
void sinsp::set_filter(string filter)
{
	if(m_filter != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("filter can only be set once");
	}

	m_filter = new sinsp_filter(filter, this);
}
#endif

#ifdef GATHER_INTERNAL_STATS
sinsp_stats sinsp::get_stats()
{
	scap_stats stats;

	//
	// Get capture stats from scap
	//
	if(m_h)
	{
		scap_get_stats(m_h, &stats);

		m_stats.m_n_seen_evts = stats.n_evts;
		m_stats.m_n_drops = stats.n_drops;
		m_stats.m_n_preemptions = stats.n_preemptions;
	}
	else
	{
		m_stats.m_n_seen_evts = 0;
		m_stats.m_n_drops = 0;
		m_stats.m_n_preemptions = 0;
	}

	//
	// Count the number of threads and fds by scanning the tables,
	// and update the thread-related stats.
	//
	if(m_thread_manager)
	{
		m_thread_manager->update_statistics();
	}

	//
	// Count the number of transactions
	//
	if(m_trans_table)
	{
		m_stats.m_n_transactions = m_trans_table->get_size();
	}

	//
	// Return the result
	//

	return m_stats;
}
#endif

sinsp_connection* sinsp::get_connection(const ipv4tuple& tuple, uint64_t timestamp)
{
	sinsp_connection* connection = m_ipv4_connections->get_connection(tuple, timestamp);
	if(NULL == connection)
	{
		// try to find the connection with source/destination reversed
		ipv4tuple tuple_reversed;
		tuple_reversed.m_fields.m_sip = tuple.m_fields.m_dip;
		tuple_reversed.m_fields.m_dip = tuple.m_fields.m_sip;
		tuple_reversed.m_fields.m_sport = tuple.m_fields.m_dport;
		tuple_reversed.m_fields.m_dport = tuple.m_fields.m_sport;
		tuple_reversed.m_fields.m_l4proto = tuple.m_fields.m_l4proto;
		connection = m_ipv4_connections->get_connection(tuple_reversed, timestamp);
		if(NULL != connection)
		{
			((ipv4tuple*)&tuple)->m_fields = tuple_reversed.m_fields;
		}
	}

	return connection;
}

sinsp_connection* sinsp::get_connection(const unix_tuple& tuple, uint64_t timestamp)
{
	return m_unix_connections->get_connection(tuple, timestamp);
}

sinsp_connection* sinsp::get_connection(const uint64_t ino, uint64_t timestamp)
{
	return m_pipe_connections->get_connection(ino, timestamp);
}

void sinsp::set_log_callback(sinsp_logger_callback cb)
{
	g_logger.add_callback_log(cb);
}

void sinsp::set_analyzer_callback(analyzer_callback_interface* cb)
{
	if(m_analyzer == NULL)
	{
		m_analyzer_callback = cb;
	}
	else
	{
		m_analyzer->set_sample_callback(cb);
	}
}

const scap_machine_info* sinsp::get_machine_info()
{
	return m_machine_info;
}

const unordered_map<uint32_t, scap_userinfo*>* sinsp::get_userlist()
{
	return &m_userlist;
}

const unordered_map<uint32_t, scap_groupinfo*>* sinsp::get_grouplist()
{
	return &m_grouplist;
}

#ifdef HAS_FILTERING
void sinsp::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
	sinsp_utils::get_filtercheck_fields_info(list);
}
#else
void sinsp::get_filtercheck_fields_info(OUT vector<const filter_check_info*>* list)
{
}
#endif