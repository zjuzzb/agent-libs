#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <process.h>
#define getpid _getpid
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <endian.h>
#include <sys/syscall.h>
#endif // _WIN32
#include <google/protobuf/io/coded_stream.h>
#ifndef _WIN32
#include <google/protobuf/io/gzip_stream.h>
#endif
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using namespace google::protobuf::io;

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
#include "analyzer_fd.h"
#include "analyzer_parsers.h"

#define DUMP_TO_DISK

sinsp_analyzer::sinsp_analyzer(sinsp* inspector)
{
	m_inspector = inspector;
	m_n_flushes = 0;
	m_next_flush_time_ns = 0;
	m_prev_flush_time_ns = 0;
	m_metrics = new draiosproto::metrics;
	m_serialization_buffer = (char*)malloc(MIN_SERIALIZATION_BUF_SIZE_BYTES);
	if(!m_serialization_buffer)
	{
			char tbuf[256];
			snprintf(tbuf, sizeof(tbuf), "memory allocation error at %s:%d", __FILE__, __LINE__);
			throw sinsp_exception(string(tbuf));
	}
	m_serialization_buffer_size = MIN_SERIALIZATION_BUF_SIZE_BYTES;
	m_sample_callback = NULL;
	m_protobuf_fp = NULL;
	m_prev_sample_evtnum = 0;
	m_serialize_prev_sample_evtnum = 0;
	m_serialize_prev_sample_time = 0;
	m_client_tr_time_by_servers = 0;
	m_last_transaction_delays_update_time = 0;
	m_total_process_cpu = 0;

	m_host_transaction_delays = new sinsp_delays_info();

	m_reduced_ipv4_connections = new unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp>();

	m_procfs_parser = NULL;
	m_sched_analyzer2 = NULL;
	m_score_calculator = NULL;
	m_delay_calculator = NULL;

	m_ipv4_connections = NULL;
#ifdef HAS_UNIX_CONNECTIONS
	m_unix_connections = NULL;
#endif
#ifdef HAS_PIPE_CONNECTIONS
	m_pipe_connections = NULL;
#endif
	m_trans_table = NULL;
	m_is_sampling = false;
	m_driver_stopped_dropping = false;
	m_sampling_ratio = 1;
	m_last_dropmode_switch_time = 0;
	m_seconds_above_thresholds = 0;
	m_seconds_below_thresholds = 0;
	m_my_cpuload = -1;
	m_last_system_cpuload = 0;
	inspector->m_max_n_proc_lookups = 300;
	inspector->m_max_n_proc_socket_lookups = 3;

	m_configuration = new sinsp_configuration();

	m_mypid = -1;

	m_parser = new sinsp_analyzer_parsers(this);

	//
	// Listeners
	//
	m_thread_memory_id = inspector->reserve_thread_memory(sizeof(thread_analyzer_info));

	m_threadtable_listener = new analyzer_threadtable_listener(inspector, this);
	inspector->m_thread_manager->set_listener((sinsp_threadtable_listener*)m_threadtable_listener);

	m_fd_listener = new sinsp_analyzer_fd_listener(inspector, this);
	inspector->m_parser->m_fd_listener = m_fd_listener;
}

sinsp_analyzer::~sinsp_analyzer()
{
	if(m_metrics)
	{
		delete m_metrics;
	}

	if(m_serialization_buffer)
	{
		free(m_serialization_buffer);
	}

	if(m_score_calculator)
	{
		delete m_score_calculator;
	}

	if(m_procfs_parser)
	{
		delete m_procfs_parser;
	}

	if(m_sched_analyzer2)
	{
		delete m_sched_analyzer2;
	}

	if(m_delay_calculator)
	{
		delete m_delay_calculator;
	}

	if(m_host_transaction_delays)
	{
		delete m_host_transaction_delays;
	}

	if(m_threadtable_listener)
	{
		delete(m_threadtable_listener);
	}

	if(m_fd_listener)
	{
		delete m_fd_listener;
	}

	if(m_reduced_ipv4_connections)
	{
		delete m_reduced_ipv4_connections;
	}

	if(m_ipv4_connections)
	{
		delete m_ipv4_connections;
	}

#ifdef HAS_UNIX_CONNECTIONS
	if(m_unix_connections)
	{
		delete m_unix_connections;
	}
#endif

#ifdef HAS_PIPE_CONNECTIONS
	if(m_pipe_connections)
	{
		delete m_pipe_connections;
	}
#endif

	if(m_trans_table)
	{
		delete m_trans_table;
	}

	if(m_configuration)
	{
		delete m_configuration;
	}

	if(m_parser)
	{
		delete m_parser;
	}

	if(m_protobuf_fp != NULL)
	{
		fclose(m_protobuf_fp);
	}

	google::protobuf::ShutdownProtobufLibrary();
}

void sinsp_analyzer::on_capture_start()
{
	if(m_procfs_parser != NULL)
	{
		throw sinsp_exception("analyzer can be opened only once");
	}

	//
	// Start dropping of non-critical events
	//
	if(m_configuration->get_autodrop_enabled())
	{
		start_dropping_mode(1);
		m_is_sampling = true;
	}
	else
	{
		m_is_sampling = false;
	}

	//
	// Enable dynamic snaplen on live captures
	//
	if(m_inspector->is_live())
	{
		if(scap_enable_dynamic_snaplen(m_inspector->m_h) != SCAP_SUCCESS)
		{
			throw sinsp_exception(scap_getlasterr(m_inspector->m_h));
		}
	}

	//
	// Hardware-dependent inits
	//
	m_machine_info = m_inspector->get_machine_info();
	if(m_machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("machine info missing, analyzer can't start");
	}

	m_procfs_parser = new sinsp_procfs_parser(m_machine_info->num_cpus, m_machine_info->memory_size_bytes / 1024, m_inspector->m_islive);
	m_procfs_parser->get_global_cpu_load(&m_old_global_total_jiffies);

	m_sched_analyzer2 = new sinsp_sched_analyzer2(m_inspector, m_machine_info->num_cpus);
	m_score_calculator = new sinsp_scores(m_inspector, m_sched_analyzer2);
	m_delay_calculator = new sinsp_delays(this, m_machine_info->num_cpus);

	m_host_server_transactions = vector<vector<sinsp_trlist_entry>>(m_machine_info->num_cpus);
	m_host_client_transactions = vector<vector<sinsp_trlist_entry>>(m_machine_info->num_cpus);

	//
	// Allocations
	//
	ASSERT(m_ipv4_connections == NULL);
	m_ipv4_connections = new sinsp_ipv4_connection_manager(m_inspector);
#ifdef HAS_UNIX_CONNECTIONS
	m_unix_connections = new sinsp_unix_connection_manager(m_inspector);
#endif
#ifdef HAS_PIPE_CONNECTIONS
	m_pipe_connections = new sinsp_pipe_connection_manager(m_inspector);
#endif
	m_trans_table = new sinsp_transaction_table(m_inspector);

	//
	// Notify the scheduler analyzer
	//
	ASSERT(m_sched_analyzer2 != NULL);
	m_sched_analyzer2->on_capture_start();
	m_parser->on_capture_start();
}

void sinsp_analyzer::set_sample_callback(analyzer_callback_interface* cb)
{
	ASSERT(cb != NULL);
	ASSERT(m_sample_callback == NULL);
	m_sample_callback = cb;
}

sinsp_configuration* sinsp_analyzer::get_configuration()
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if(m_inspector->m_h != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("Attempting to set the configuration while the inspector is capturing");
	}

	return m_configuration;
}

void sinsp_analyzer::set_configuration(const sinsp_configuration& configuration)
{
	//
	// The configuration can currently only be read or modified before the capture starts
	//
	if(m_inspector->m_h != NULL)
	{
		ASSERT(false);
		throw sinsp_exception("Attempting to set the configuration while the inspector is capturing");
	}

	*m_configuration = configuration;
}

void sinsp_analyzer::remove_expired_connections(uint64_t ts)
{
	m_ipv4_connections->remove_expired_connections(ts);
#ifdef HAS_UNIX_CONNECTIONS
	m_unix_connections->remove_expired_connections(ts);
#endif
#ifdef HAS_PIPE_CONNECTIONS
	m_pipe_connections->remove_expired_connections(ts);
#endif
}

sinsp_connection* sinsp_analyzer::get_connection(const ipv4tuple& tuple, uint64_t timestamp)
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

#ifdef HAS_UNIX_CONNECTIONS
sinsp_connection* sinsp_analyzer::get_connection(const unix_tuple& tuple, uint64_t timestamp)
{
	return m_unix_connections->get_connection(tuple, timestamp);
}

sinsp_connection* sinsp_analyzer::get_connection(const uint64_t ino, uint64_t timestamp)
{
	return m_pipe_connections->get_connection(ino, timestamp);
}
#endif

char* sinsp_analyzer::serialize_to_bytebuf(OUT uint32_t *len, bool compressed)
{
	//
	// Find out how many bytes we need for the serialization
	//
	uint32_t full_len = m_metrics->ByteSize();

	//
	// If the buffer is not big enough, expand it
	//
	if(m_serialization_buffer_size < full_len)
	{
		if(full_len >= MAX_SERIALIZATION_BUF_SIZE_BYTES)
		{
			g_logger.log("Metrics sample too big. Dropping it.", sinsp_logger::SEV_ERROR);
			return NULL;
		}

		m_serialization_buffer = (char*)realloc(m_serialization_buffer, full_len);

		if(!m_serialization_buffer)
		{
			char *estr = g_logger.format(sinsp_logger::SEV_CRITICAL, "memory allocation error at %s:%d", __FILE__, __LINE__);
			throw sinsp_exception(estr);
		}

		m_serialization_buffer_size = full_len;
	}

	//
	// Do the serialization
	//
	if(compressed)
	{
#ifdef _WIN32
		ASSERT(false);
		throw sinsp_exception("compression in agent protocol not implemented under windows");
		return NULL;
#else
        ArrayOutputStream array_output(m_serialization_buffer, full_len);
        GzipOutputStream gzip_output(&array_output);

        m_metrics->SerializeToZeroCopyStream(&gzip_output);
        gzip_output.Close();

        uint32_t compressed_size = (uint32_t) array_output.ByteCount();
        if(compressed_size > full_len)
        {
            ASSERT(false);
            char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "unexpected serialization buffer size");
            throw sinsp_exception(estr);
        }

        *len = compressed_size;
        return m_serialization_buffer;
#endif
	}
	else
	{
		//
		// Reserve 4 bytes at the beginning of the string for the length
		//
		ArrayOutputStream array_output(m_serialization_buffer, full_len);
		m_metrics->SerializeToZeroCopyStream(&array_output);

        *len = full_len;
        return m_serialization_buffer;
	}
}

void sinsp_analyzer::serialize(sinsp_evt* evt, uint64_t ts)
{

	uint64_t nevts = 0;

	if(evt)
	{
		nevts = evt->get_num() - m_serialize_prev_sample_evtnum;
		m_serialize_prev_sample_evtnum = evt->get_num();

		//
		// Subsampling can cause repeated samples, which we skip here
		//
		if(m_serialize_prev_sample_time != 0)
		{
			if(ts == m_serialize_prev_sample_time)
			{
				return;
			}
		}

		m_serialize_prev_sample_time = ts;
	}

	if(m_sample_callback != NULL)
	{
		m_sample_callback->sinsp_analyzer_data_ready(ts, nevts, m_metrics);
	}

	if(m_configuration->get_emit_metrics_to_file())
	{
		char fname[128];
		uint32_t buflen;

		//
		// Serialize the protobuf
		//
		char* buf = sinsp_analyzer::serialize_to_bytebuf(&buflen,
			m_configuration->get_compress_metrics());

		g_logger.format(sinsp_logger::SEV_ERROR,
			"ts=%" PRIu64 ", len=%" PRIu32 ", ne=%" PRIu64,
			ts / 100000000,
			buflen, nevts);

		if(!buf)
		{
			return;
		}

		snprintf(fname, sizeof(fname), "%s%" PRIu64 ".dam",
			m_configuration->get_metrics_directory().c_str(),
			ts / 1000000000);

		//
		// Write the data to file
		//
		//fp = fopen(fname, "wb");

		//if(!fp)
		//{
		//	char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't open file %s", fname);
		//	throw sinsp_exception(estr);
		//}

		//if(fwrite(buf, buflen, 1, fp) != 1)
		//{
		//	ASSERT(false);
		//	char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't write actual data to file %s", fname);
		//	throw sinsp_exception(estr);
		//}

		//fclose(fp);

		//
		// Write the string version to file
		//
		string pbstr = m_metrics->DebugString();

		snprintf(fname, sizeof(fname), "%s%" PRIu64 ".dams",
			m_configuration->get_metrics_directory().c_str(),
			ts / 1000000000);

		if(m_protobuf_fp == NULL)
		{
			m_protobuf_fp = fopen(fname, "w");

			if(!m_protobuf_fp)
			{
				char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't open file %s", fname);
				throw sinsp_exception(estr);
			}
		}

		if(fwrite(pbstr.c_str(), pbstr.length(), 1, m_protobuf_fp) != 1)
		{
			ASSERT(false);
			char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't write actual data to file %s", fname);
			throw sinsp_exception(estr);
		}
	}
}

void sinsp_analyzer::filter_top_programs(unordered_map<size_t, sinsp_threadinfo*>* progtable, bool cs_only, uint32_t howmany)
{
	uint32_t j;

	vector<sinsp_threadinfo*> prog_sortable_list;

	unordered_map<size_t, sinsp_threadinfo*>::iterator ptit;

	for(ptit = progtable->begin(); ptit != progtable->end(); ++ptit)
	{
		if(cs_only)
		{
			int is_cs = (ptit->second->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
					thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT | thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT));

			if(is_cs)
			{
				prog_sortable_list.push_back(ptit->second);
			}
		}
		else
		{
			prog_sortable_list.push_back(ptit->second);
		}
	}

	if(prog_sortable_list.size() <= howmany)
	{
		for(j = 0; j < prog_sortable_list.size(); j++)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}

		return;
	}

	//
	// Mark the top CPU consumers
	//
	if(cs_only)
	{
		partial_sort(prog_sortable_list.begin(), 
			prog_sortable_list.begin() + howmany, 
			prog_sortable_list.end(),
			(cs_only)?threadinfo_cmp_cpu_cs:threadinfo_cmp_cpu);

		for(j = 0; j < howmany; j++)
		{
			if(prog_sortable_list[j]->m_ainfo->m_cpuload > 0)
			{
				prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
			}
			else
			{
				break;
			}
		}
	}
	else
	{
		partial_sort(prog_sortable_list.begin(), 
			prog_sortable_list.begin() + howmany, 
			prog_sortable_list.end(),
			(cs_only)?threadinfo_cmp_cpu_cs:threadinfo_cmp_cpu);

		for(j = 0; j < prog_sortable_list.size(); j++)
		{
			if(j >= howmany || prog_sortable_list[j]->m_ainfo->m_cpuload <= 0)
			{
				prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = true;
			}
		}
	}

	//
	// Mark the top memory consumers
	//
	partial_sort(prog_sortable_list.begin(), 
		prog_sortable_list.begin() + howmany, 
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_memory_cs:threadinfo_cmp_memory);

	for(j = 0; j < howmany; j++)
	{
		if(prog_sortable_list[j]->m_vmsize_kb > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top disk I/O consumers
	//
	partial_sort(prog_sortable_list.begin(), 
		prog_sortable_list.begin() + howmany, 
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_io_cs:threadinfo_cmp_io);

	for(j = 0; j < howmany; j++)
	{
		ASSERT(prog_sortable_list[j]->m_ainfo->m_procinfo != NULL);

		if(prog_sortable_list[j]->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top network I/O consumers
	//
	partial_sort(prog_sortable_list.begin(), 
		prog_sortable_list.begin() + howmany, 
		prog_sortable_list.end(),
		(cs_only)?threadinfo_cmp_net_cs:threadinfo_cmp_net);

	for(j = 0; j < howmany; j++)
	{
		ASSERT(prog_sortable_list[j]->m_ainfo->m_procinfo != NULL);

		if(prog_sortable_list[j]->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 0)
		{
			prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
		}
		else
		{
			break;
		}
	}

	//
	// Mark the top transaction generators
	//
	//partial_sort(prog_sortable_list.begin(), 
	//	prog_sortable_list.begin() + howmany, 
	//	prog_sortable_list.end(),
	//	threadinfo_cmp_transactions);

	//for(j = 0; j < howmany; j++)
	//{
	//	if(prog_sortable_list[j]->m_ainfo->m_procinfo->m_proc_transaction_metrics.m_counter.get_tot_count() > 0)
	//	{
	//		prog_sortable_list[j]->m_ainfo->m_procinfo->m_exclude_from_sample = false;
	//	}
	//	else
	//	{
	//		break;
	//	}
	//}
}

void sinsp_analyzer::filter_top_noncs_programs(unordered_map<size_t, sinsp_threadinfo*>* progtable)
{
	filter_top_programs(progtable, 
		false,
		TOP_PROCESSES_IN_SAMPLE);
}

void sinsp_analyzer::filter_top_cs_programs(unordered_map<size_t, sinsp_threadinfo*>* progtable)
{
	filter_top_programs(progtable, 
		true,
		TOP_PROCESSES_IN_SAMPLE);
}

void sinsp_analyzer::emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof, sinsp_analyzer::flush_flags flshflags)
{
	int64_t delta;
	sinsp_evt::category* cat;
	sinsp_evt::category tcat;
	m_server_programs.clear();
	threadinfo_map_iterator_t it;
	set<string> included_programs;
	set<uint64_t> proctids;
	unordered_map<size_t, sinsp_threadinfo*> progtable;

	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, 
			"thread table size:%d",
			m_inspector->m_thread_manager->get_thread_count());
	}

	if(m_ipv4_connections->get_n_drops() != 0)
	{
		if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			g_logger.format(sinsp_logger::SEV_ERROR, 
				"IPv4 table size:%d",
				m_ipv4_connections->m_connections.size());
		}

		m_ipv4_connections->clear_n_drops();
	}

	//
	// Run the periodic /proc scan and use it to prune the process table
	//
	if(m_n_flushes % PROC_BASED_THREAD_PRUNING_INTERVAL == 
		(PROC_BASED_THREAD_PRUNING_INTERVAL - 1))
	{
		m_procfs_parser->get_tid_list(&proctids);
	}

	//
	// Extract global CPU info
	//
	uint64_t cur_global_total_jiffies;
	if(m_inspector->m_islive)
	{
		if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			m_procfs_parser->get_global_cpu_load(&cur_global_total_jiffies);
		}
	}
	else
	{
		cur_global_total_jiffies = 0;
	}

	//
	// Propagate the memory information from child thread to main thread:
	// since memory is updated at context-switch intervals, it can happen
	// that the "main" thread stays mostly idle, without getting memory events then
	//
	for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); ++it)
	{
		sinsp_threadinfo* mtinfo = it->second.get_main_thread();
		sinsp_threadinfo* tinfo = &it->second;

		if(tinfo->m_vmsize_kb > mtinfo->m_vmsize_kb)
		{
			mtinfo->m_vmsize_kb = tinfo->m_vmsize_kb;
		}

		if(tinfo->m_vmrss_kb > mtinfo->m_vmrss_kb)
		{
			mtinfo->m_vmrss_kb = tinfo->m_vmrss_kb;
		}

		if(tinfo->m_vmswap_kb > mtinfo->m_vmswap_kb)
		{
			mtinfo->m_vmswap_kb = tinfo->m_vmswap_kb;
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// First pass of the list of threads: emit the metrics (if defined)
	// and aggregate them into processes
	///////////////////////////////////////////////////////////////////////////
	for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); ++it)
	{		
		sinsp_threadinfo* tinfo = &it->second;
		thread_analyzer_info* ainfo = tinfo->m_ainfo;

		//
		// Attribute the last pending event to this second
		//
		if(m_prev_flush_time_ns != 0)
		{
			delta = m_prev_flush_time_ns - tinfo->m_lastevent_ts;

			if(delta > (int64_t)sample_duration)
			{
				delta = (tinfo->m_lastevent_ts / sample_duration * sample_duration + sample_duration) - 
					tinfo->m_lastevent_ts;
			}

			tinfo->m_lastevent_ts = m_prev_flush_time_ns;

			if(PPME_IS_ENTER(tinfo->m_lastevent_type))
			{
				cat = &tinfo->m_lastevent_category;
			}
			else
			{
				tcat.m_category = EC_PROCESSING;
				tcat.m_subcategory = sinsp_evt::SC_NONE;
				cat = &tcat;
			}

			add_syscall_time(&ainfo->m_metrics, 
				cat, 
				delta,
				0,
				false);

			//
			// Flag the thread so we know that part of this event has already been attributed
			//
			ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_PARTIAL_METRIC;
		}

		//
		// Some assertions to validate that everything looks like expected
		//
#ifdef _DEBUG
		sinsp_counter_time ttot;
		ainfo->m_metrics.get_total(&ttot);
		if(!m_inspector->m_islive)
		{
			ASSERT(is_eof || ttot.m_time_ns % sample_duration == 0);
		}
#endif

		//
		// Go through the FD list to flush the transactions that haven't been active for a while
		//
		uint64_t trtimeout;
		bool is_subsampling;
		
		if(flshflags == sinsp_analyzer::DF_NONE)
		{
			trtimeout = TRANSACTION_TIMEOUT_NS;
			is_subsampling = false;
		}
		else
		{
			trtimeout = TRANSACTION_TIMEOUT_SUBSAMPLING_NS;
			is_subsampling = true;
		}

		ainfo->flush_inactive_transactions(m_prev_flush_time_ns, trtimeout, is_subsampling);

		//
		// If this is a process, compute CPU load and memory usage
		//
		ainfo->m_cpuload = 0;

		if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			if(tinfo->is_main_thread())
			{
				if(m_inspector->m_islive)
				{
					//
					// It's pointless to try to get the CPU load if the process has been closed
					//
					if((tinfo->m_flags & PPM_CL_CLOSED) == 0)
					{
						ainfo->m_cpuload = m_procfs_parser->get_process_cpu_load(tinfo->m_pid, 
							&ainfo->m_old_proc_jiffies, 
							cur_global_total_jiffies - m_old_global_total_jiffies);

						m_total_process_cpu += ainfo->m_cpuload;
					}
				}
			}
		}
		
		//
		// Add this thread's counters to the process ones...
		//
		ASSERT(tinfo->m_program_hash != 0);

		auto mtinfo = progtable.emplace(tinfo->m_program_hash, &it->second).first->second;
		if(mtinfo->m_tid == tinfo->m_tid)
		{
			ainfo->set_main_program_thread(true);
		}
		else
		{
			ainfo->set_main_program_thread(false);
		}

		ASSERT(mtinfo != NULL);

		ainfo->m_main_thread_pid = mtinfo->m_pid;

		mtinfo->m_ainfo->add_all_metrics(ainfo);

		//
		// ... And to the host ones
		//
		m_host_transaction_counters.add(&ainfo->m_external_transaction_metrics);

		if(mtinfo->m_ainfo->m_procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
		{
			m_server_programs.insert(mtinfo->m_tid);
			m_client_tr_time_by_servers += ainfo->m_external_transaction_metrics.get_counter()->m_time_ns_out;
		}

		if(m_inspector->m_islive)
		{
			if(it->first == m_mypid)
			{
				m_my_cpuload = ainfo->m_cpuload;
			}
		}
	}

	//
	// Filter out the programs that didn't generate enough activity to go in the sample.
	// Note: we only do this when we're live, because in offline captures we don't have
	//       process CPU and memory.
	//
	if(m_inspector->m_islive)
	{
		if(progtable.size() > TOP_PROCESSES_IN_SAMPLE)
		{
			filter_top_noncs_programs(&progtable);
			filter_top_cs_programs(&progtable);
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// Second pass of the list of threads: aggreagate threads into processes 
	// or programs.
	///////////////////////////////////////////////////////////////////////////
	for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); 
		)
	{
		sinsp_threadinfo* tinfo = &it->second;

		//
		// If this is the main thread of a process, add an entry into the processes
		// section too
		//
#ifdef ANALYZER_EMITS_PROGRAMS
		if(tinfo->m_ainfo->is_main_program_thread())
#else
		if(tinfo->is_main_thread())
#endif
		{
			sinsp_procinfo* procinfo = tinfo->m_ainfo->m_procinfo;

			if(proctids.size() != 0)
			{
				if(proctids.find(it->first) == proctids.end())
				{
					tinfo->m_flags |= PPM_CL_CLOSED;
				}
			}

#ifdef ANALYZER_EMITS_PROCESSES
			sinsp_counter_time tot;
	
			ASSERT(procinfo != NULL);

			procinfo->m_proc_metrics.get_total(&tot);
			if(!m_inspector->m_islive)
			{
				ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);
			}

			//
			// Inclusion logic
			//
			// Keep:
			//  - top 30 clients/servers
			//  - top 30 programs that were active
			int is_cs = (tinfo->m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
					thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT | thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT));

			bool include;

			if(is_cs)
			{
				//
				// If this is a client or a server, it didn't generate any activity in the sample,
				// and another program with the same name has already been included, we can safely
				// exclude it, since its presence would be completely redundant
				//
				include = (!tinfo->m_ainfo->m_procinfo->m_exclude_from_sample);

				if(include && (tot.m_count == 0 && procinfo->m_cpuload == 0))
				{
					if(included_programs.find(tinfo->m_exe) != included_programs.end())
					{
						include = false;
					}
				}
			}
			else
			{
				//
				// If this NOT is a client or a server, skip it if it didn't generate any activity.
				//
				include = (!tinfo->m_ainfo->m_procinfo->m_exclude_from_sample);
			}

			if(include)
			{
				included_programs.insert(tinfo->m_exe);

#ifdef ANALYZER_EMITS_PROGRAMS
				draiosproto::program* prog = m_metrics->add_programs();
				draiosproto::process* proc = prog->mutable_procinfo();

				//for(int64_t pid : procinfo->m_program_pids)
				//{
				//	prog->add_pids(pid);
				//}
				prog->add_pids(it->second.m_pid);
#else // ANALYZER_EMITS_PROGRAMS
				draiosproto::process* proc = m_metrics->add_processes();
#endif // ANALYZER_EMITS_PROGRAMS

				//
				// Basic values
				//
				if((tinfo->m_flags & PPM_CL_NAME_CHANGED) ||
					(m_n_flushes % PROCINFO_IN_SAMPLE_INTERVAL == (PROCINFO_IN_SAMPLE_INTERVAL - 1)))
				{
					proc->mutable_details()->set_comm(tinfo->m_comm);
					proc->mutable_details()->set_exe(tinfo->m_exe);
					for(vector<string>::const_iterator arg_it = tinfo->m_args.begin(); 
						arg_it != tinfo->m_args.end(); ++arg_it)
					{
						if(*arg_it != "")
						{
							proc->mutable_details()->add_args(*arg_it);
						}
					}

					tinfo->m_flags &= ~PPM_CL_NAME_CHANGED;
				}

				//
				// client-server role
				//
				uint32_t netrole = 0;

				if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER)
				{
					netrole |= draiosproto::IS_REMOTE_IPV4_SERVER;
				}
				else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER)
				{
					netrole |= draiosproto::IS_LOCAL_IPV4_SERVER;
				}
				else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_SERVER)
				{
					netrole |= draiosproto::IS_UNIX_SERVER;
				}

				if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT)
				{
					netrole |= draiosproto::IS_REMOTE_IPV4_CLIENT;
				}
				else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT)
				{
					netrole |= draiosproto::IS_LOCAL_IPV4_CLIENT;
				}
				else if(tinfo->m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_CLIENT)
				{
					netrole |= draiosproto::IS_UNIX_CLIENT;
				}

				proc->set_netrole(netrole);

				//
				// CPU utilization
				//
				if(procinfo->m_cpuload >= 0)
				{
					if(procinfo->m_cpuload > (int32_t)(100 * m_machine_info->num_cpus))
					{
						procinfo->m_cpuload = (int32_t)100 * m_machine_info->num_cpus;
					}

					proc->mutable_resource_counters()->set_cpu_pct((uint32_t)(procinfo->m_cpuload * 100));
					proc->mutable_resource_counters()->set_resident_memory_usage_kb(procinfo->m_vmrss_kb);
					proc->mutable_resource_counters()->set_virtual_memory_usage_kb(procinfo->m_vmsize_kb);
					proc->mutable_resource_counters()->set_swap_memory_usage_kb(procinfo->m_vmswap_kb);
					proc->mutable_resource_counters()->set_major_pagefaults(procinfo->m_pfmajor);
					proc->mutable_resource_counters()->set_minor_pagefaults(procinfo->m_pfminor);
				}
				else
				{
					proc->mutable_resource_counters()->set_cpu_pct(0);
					proc->mutable_resource_counters()->set_resident_memory_usage_kb(0);
					proc->mutable_resource_counters()->set_virtual_memory_usage_kb(0);
					proc->mutable_resource_counters()->set_swap_memory_usage_kb(0);
					proc->mutable_resource_counters()->set_major_pagefaults(0);
					proc->mutable_resource_counters()->set_minor_pagefaults(0);
				}

				if(tot.m_count != 0)
				{
					sinsp_delays_info* prog_delays = &procinfo->m_transaction_delays;
					m_delay_calculator->compute_program_delays(tinfo, prog_delays);

					//
					// Main metrics
					//
					procinfo->m_proc_metrics.to_protobuf(proc->mutable_tcounters(), m_sampling_ratio);

					//
					// Transaction-related metrics
					//
					if(prog_delays->m_local_processing_delay_ns != -1)
					{
						proc->set_transaction_processing_delay(prog_delays->m_local_processing_delay_ns * m_sampling_ratio);
						proc->set_merged_server_delay(prog_delays->m_merged_server_delay * m_sampling_ratio);
						proc->set_next_tiers_delay(prog_delays->m_merged_client_delay * m_sampling_ratio);
					}

					procinfo->m_proc_transaction_metrics.to_protobuf(proc->mutable_transaction_counters(), 
						proc->mutable_min_transaction_counters(),
						proc->mutable_max_transaction_counters(),
						m_sampling_ratio);

					//
					// Health-related metrics
					//
					if(procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
					{
						sinsp_score_info scores = m_score_calculator->get_process_capacity_score(tinfo,
							prog_delays,
							(uint32_t)tinfo->m_ainfo->m_procinfo->m_n_transaction_threads,
							m_prev_flush_time_ns, sample_duration);

							procinfo->m_capacity_score = scores.m_current_capacity;
							procinfo->m_stolen_capacity_score = scores.m_stolen_capacity;
					}
					else
					{
						procinfo->m_capacity_score = -1;
						procinfo->m_stolen_capacity_score = 0;
					}

					//
					// Update the host capcity score
					//
					if(procinfo->m_capacity_score != -1)
					{
						m_host_metrics.add_capacity_score(procinfo->m_capacity_score,
							procinfo->m_stolen_capacity_score,
							procinfo->m_external_transaction_metrics.get_counter()->m_count_in);
					}

					proc->mutable_resource_counters()->set_capacity_score((uint32_t)(procinfo->m_capacity_score * 100));
					proc->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(procinfo->m_stolen_capacity_score * 100));
					proc->mutable_resource_counters()->set_connection_queue_usage_pct(procinfo->m_connection_queue_usage_pct);
					proc->mutable_resource_counters()->set_fd_usage_pct(procinfo->m_fd_usage_pct);
					proc->mutable_resource_counters()->set_fd_count(procinfo->m_fd_count);

					//
					// Error-related metrics
					//
					procinfo->m_syscall_errors.to_protobuf(proc->mutable_syscall_errors(), m_sampling_ratio);

					//
					// Protocol tables
					//
					procinfo->m_protostate.to_protobuf(proc->mutable_protos(),
						m_sampling_ratio);

#if 1
					if(procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
					{
						uint64_t trtimein = procinfo->m_proc_transaction_metrics.get_counter()->m_time_ns_in;
						uint64_t trtimeout = procinfo->m_proc_transaction_metrics.get_counter()->m_time_ns_out;
						uint32_t trcountin = procinfo->m_proc_transaction_metrics.get_counter()->m_count_in;
						uint32_t trcountout = procinfo->m_proc_transaction_metrics.get_counter()->m_count_out;

						if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
						{
							g_logger.format(sinsp_logger::SEV_DEBUG,
								" %s (%" PRIu64 ")%" PRIu64 " h:%.2f(s:%.2f) cpu:%.2f %%f:%" PRIu32 " %%c:%" PRIu32,
								tinfo->m_comm.c_str(),
								tinfo->m_tid,
								(uint64_t)tinfo->m_ainfo->m_procinfo->m_program_pids.size(),
								procinfo->m_capacity_score,
								procinfo->m_stolen_capacity_score,
								(float)procinfo->m_cpuload,
								procinfo->m_fd_usage_pct,
								procinfo->m_connection_queue_usage_pct);

							g_logger.format(sinsp_logger::SEV_DEBUG,
								"  trans)in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
								procinfo->m_proc_transaction_metrics.get_counter()->m_count_in * m_sampling_ratio,
								procinfo->m_proc_transaction_metrics.get_counter()->m_count_out * m_sampling_ratio,
								trcountin? ((double)trtimein) / sample_duration : 0,
								trcountout? ((double)trtimeout) / sample_duration : 0,
								(prog_delays)?((double)prog_delays->m_merged_server_delay) / sample_duration : 0,
								(prog_delays)?((double)prog_delays->m_merged_client_delay) / sample_duration : 0,
								(prog_delays)?((double)prog_delays->m_local_processing_delay_ns) / sample_duration : 0);

							g_logger.format(sinsp_logger::SEV_DEBUG,
								"  time)proc:%.2lf%% file:%.2lf%%(in:%" PRIu32 "b/%" PRIu32" out:%" PRIu32 "b/%" PRIu32 ") net:%.2lf%% other:%.2lf%%",
								procinfo->m_proc_metrics.get_processing_percentage() * 100,
								procinfo->m_proc_metrics.get_file_percentage() * 100,
								procinfo->m_proc_metrics.m_tot_io_file.m_bytes_in,
								procinfo->m_proc_metrics.m_tot_io_file.m_count_in,
								procinfo->m_proc_metrics.m_tot_io_file.m_bytes_out,
								procinfo->m_proc_metrics.m_tot_io_file.m_count_out,
								procinfo->m_proc_metrics.get_net_percentage() * 100,
								procinfo->m_proc_metrics.get_other_percentage() * 100);
						}
					}
#endif

#ifdef _DEBUG
					double totpct = procinfo->m_proc_metrics.get_processing_percentage() +
						procinfo->m_proc_metrics.get_file_percentage() + 
						procinfo->m_proc_metrics.get_net_percentage() +
						procinfo->m_proc_metrics.get_other_percentage();

					ASSERT(totpct > 0.99);
					ASSERT(totpct < 1.01);
#endif // _DEBUG
				}
#endif // ANALYZER_EMITS_PROCESSES
			}

			//
			// Update the host metrics with the info coming from this process
			//
			if(tot.m_count != 0 || procinfo->m_cpuload != 0)
			{
				if(procinfo != NULL)
				{
					if(procinfo->m_proc_transaction_metrics.get_counter()->m_count_in != 0)
					{
						m_host_req_metrics.add(&procinfo->m_proc_metrics);
					}

					//
					// Note how we only include server processes.
					// That's because these are transaction time metrics, and therefore we don't 
					// want to use processes that don't serve transactions.
					//
					m_host_metrics.add(procinfo);
				}
				else
				{
					ASSERT(false);
				}
			}

		}

		//
		// Has this thread been closed druring this sample?
		//
		if(tinfo->m_flags & PPM_CL_CLOSED)
		{
			//
			// Yes, remove the thread from the table, but NOT if the event currently under processing is
			// an exit for this process. In that case we wait until next sample.
			// Note: we clear the metrics no matter what because m_thread_manager->remove_thread might
			//       not actually remove the thread if it has childs.
			//
			tinfo->m_ainfo->clear_all_metrics();

			if(evt != NULL && 
				(evt->get_type() == PPME_PROCEXIT_E || evt->get_type() == PPME_PROCEXIT_1_E)
				&& evt->m_tinfo == tinfo)
			{
				++it;
			}
			else
			{
				m_inspector->m_thread_manager->remove_thread(it++, false);
			}
		}
		else
		{
			//
			// Clear the thread metrics, so we're ready for the next sample
			//
			tinfo->m_ainfo->clear_all_metrics();
			++it;
		}
	}

	if(flshflags != sinsp_analyzer::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		m_old_global_total_jiffies = cur_global_total_jiffies;
	}
}

//
// Strategy:
//  - sport is *always* masked to zero
//  - if there are more than MAX_N_EXTERNAL_CLIENTS external client connections,
//    external client IPs are masked to zero
//
void sinsp_analyzer::emit_aggregated_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
	process_tuple tuple;
	bool aggregate_external_clients = false;
	set<uint32_t> unique_external_ips;

	m_reduced_ipv4_connections->clear();

	//
	// First partial pass to determine if external connections need to be coalesced
	//
	for(cit = m_ipv4_connections->m_connections.begin(); 
		cit != m_ipv4_connections->m_connections.end(); 
		++cit)
	{
		if(cit->second.is_server_only())
		{
			uint32_t sip = cit->first.m_fields.m_sip;

			if(!m_inspector->m_network_interfaces->is_ipv4addr_in_subnet(sip))
			{
				unique_external_ips.insert(sip);

				if(unique_external_ips.size() > MAX_N_EXTERNAL_CLIENTS)
				{
					aggregate_external_clients = true;
					break;
				}
			}
		}
	}

	//
	// Second pass to perform the aggegation
	//
	for(cit = m_ipv4_connections->m_connections.begin(); 
		cit != m_ipv4_connections->m_connections.end();)
	{
		tuple.m_fields.m_spid = cit->second.m_spid;
		tuple.m_fields.m_dpid = cit->second.m_dpid;
		tuple.m_fields.m_sip = cit->first.m_fields.m_sip;
		tuple.m_fields.m_dip = cit->first.m_fields.m_dip;
		tuple.m_fields.m_sport = 0;
		tuple.m_fields.m_dport = cit->first.m_fields.m_dport;
		tuple.m_fields.m_l4proto = cit->first.m_fields.m_l4proto;

		if(tuple.m_fields.m_sip != 0 && tuple.m_fields.m_dip != 0)
		{
			if(!cit->second.is_client_and_server())
			{
				if(cit->second.is_server_only())
				{
					//
					// If external client aggregation is enabled, this is a server connection, and 
					// the client address is outside the subnet, mask it so it gets aggregated
					//
					if(aggregate_external_clients)
					{
						if(!m_inspector->m_network_interfaces->is_ipv4addr_in_subnet(cit->first.m_fields.m_sip))
						{
							tuple.m_fields.m_sip = 0;
						}
					}

					//
					// Add this connection's bytes to the host network volume
					//
					m_io_net.add_in(cit->second.m_metrics.m_server.m_count_in, 0, cit->second.m_metrics.m_server.m_bytes_in);
					m_io_net.add_out(cit->second.m_metrics.m_server.m_count_out, 0, cit->second.m_metrics.m_server.m_bytes_out);
				}
				else
				{
					//
					// Add this connection's bytes to the host network volume
					//
					ASSERT(cit->second.is_client_only())
					m_io_net.add_in(cit->second.m_metrics.m_client.m_count_in, 0, cit->second.m_metrics.m_client.m_bytes_in);
					m_io_net.add_out(cit->second.m_metrics.m_client.m_count_out, 0, cit->second.m_metrics.m_client.m_bytes_out);
				}
			}

			//
			// Look for the entry in the reduced connection table.
			// Note: we don't export connections whose sip or dip is zero.
			//
			sinsp_connection& conn = (*m_reduced_ipv4_connections)[tuple];

			if(conn.m_timestamp == 0)
			{
				//
				// New entry.
				// Structure copy the connection info.
				//
				conn = cit->second;
				conn.m_timestamp = 1;
			}
			else
			{
				//
				// Existing entry.
				// Add this connection's metrics to the aggregated connection's ones.
				//
				conn.m_metrics.add(&cit->second.m_metrics);
				conn.m_transaction_metrics.add(&cit->second.m_transaction_metrics);
				conn.m_timestamp++;
			}
		}

		//
		// Has this connection been closed druring this sample?
		//
		if(cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_ipv4_connections->m_connections.erase(cit++);
		}
		else
		{
			//
			// Clear the transaction metrics, so we're ready for the next sample
			//
			cit->second.clear();
			++cit;
		}
	}

	//
	// Emit the aggregated table into the sample
	//
	unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp>::iterator acit;
	for(acit = m_reduced_ipv4_connections->begin(); 
		acit != m_reduced_ipv4_connections->end(); ++acit)
	{
		//
		// Skip connection that had no activity during the sample
		//
		if(!acit->second.is_active())
		{
			continue;
		}

		//
		// Find the main program pids
		//
		int64_t prog_spid = 0;
		int64_t prog_dpid = 0;

		if(acit->second.m_spid != 0)
		{
			auto tinfo = m_inspector->get_thread(acit->second.m_spid, false, true);
			if(tinfo == NULL)
			{
				//
				// No thread info for this connection?
				//
				continue;
			}

			prog_spid = tinfo->m_ainfo->m_main_thread_pid;
		}

		if(acit->second.m_dpid != 0)
		{
			auto tinfo = m_inspector->get_thread(acit->second.m_dpid, false, true);
			if(tinfo == NULL)
			{
				//
				// No thread info for this connection?
				//
				continue;
			}

			prog_dpid = tinfo->m_ainfo->m_main_thread_pid;
		}

		//
		// Add the connection to the protobuf
		//
		draiosproto::ipv4_connection* conn = m_metrics->add_ipv4_connections();
		draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

		tuple->set_sip(htonl(acit->first.m_fields.m_sip));
		tuple->set_dip(htonl(acit->first.m_fields.m_dip));
		tuple->set_sport(acit->first.m_fields.m_sport);
		tuple->set_dport(acit->first.m_fields.m_dport);
		tuple->set_l4proto(acit->first.m_fields.m_l4proto);

		conn->set_spid(prog_spid);
		conn->set_dpid(prog_dpid);

		acit->second.m_metrics.to_protobuf(conn->mutable_counters(), m_sampling_ratio);
		acit->second.m_transaction_metrics.to_protobuf(conn->mutable_counters()->mutable_transaction_counters(),
			conn->mutable_counters()->mutable_min_transaction_counters(),
			conn->mutable_counters()->mutable_max_transaction_counters(), 
			m_sampling_ratio);
		
		//
		// The timestamp field is used to count the number of sub-connections
		//
		conn->mutable_counters()->set_n_aggregated_connections((uint32_t)acit->second.m_timestamp);
	}
}

void sinsp_analyzer::emit_full_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;

	for(cit = m_ipv4_connections->m_connections.begin(); 
		cit != m_ipv4_connections->m_connections.end();)
	{
		//
		// We only include connections that had activity during the sample
		//
		if(cit->second.is_active())
		{
			draiosproto::ipv4_connection* conn = m_metrics->add_ipv4_connections();
			draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

			tuple->set_sip(htonl(cit->first.m_fields.m_sip));
			tuple->set_dip(htonl(cit->first.m_fields.m_dip));
			tuple->set_sport(cit->first.m_fields.m_sport);
			tuple->set_dport(cit->first.m_fields.m_dport);
			tuple->set_l4proto(cit->first.m_fields.m_l4proto);

			conn->set_spid(cit->second.m_spid);
			conn->set_dpid(cit->second.m_dpid);

			cit->second.m_metrics.to_protobuf(conn->mutable_counters(), m_sampling_ratio);
			cit->second.m_transaction_metrics.to_protobuf(conn->mutable_counters()->mutable_transaction_counters(),
				conn->mutable_counters()->mutable_min_transaction_counters(),
				conn->mutable_counters()->mutable_max_transaction_counters(), 
				m_sampling_ratio);
		}

		//
		// Add this connection's bytes to the host network volume
		//
		if(!cit->second.is_client_and_server())
		{
			if(cit->second.is_server_only())
			{
				m_io_net.add_in(cit->second.m_metrics.m_server.m_count_in, 0, cit->second.m_metrics.m_server.m_bytes_in);
				m_io_net.add_out(cit->second.m_metrics.m_server.m_count_out, 0, cit->second.m_metrics.m_server.m_bytes_out);
			}
			else
			{
				ASSERT(cit->second.is_client_only())
				m_io_net.add_in(cit->second.m_metrics.m_client.m_count_in, 0, cit->second.m_metrics.m_client.m_bytes_in);
				m_io_net.add_out(cit->second.m_metrics.m_client.m_count_out, 0, cit->second.m_metrics.m_client.m_bytes_out);
			}
		}

		//
		// Has this connection been closed druring this sample?
		//
		if(cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_ipv4_connections->m_connections.erase(cit++);
		}
		else
		{
			//
			// Clear the transaction metrics, so we're ready for the next sample
			//
			cit->second.clear();
			++cit;
		}
	}
}

void sinsp_analyzer::tune_drop_mode(flush_flags flshflags, double treshold_metric)
{
	//
	// Drop mode logic:
	// if we stay above DROP_UPPER_THRESHOLD for DROP_THRESHOLD_CONSECUTIVE_SECONDS, we increase the sampling,
	// if we stay above DROP_LOWER_THRESHOLD for DROP_THRESHOLD_CONSECUTIVE_SECONDS, we decrease the sampling,
	//
	uint32_t j;

	if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		if(treshold_metric >= (double)m_configuration->get_drop_upper_threshold(m_machine_info->num_cpus))
		{
			m_seconds_above_thresholds++;

			g_logger.format(sinsp_logger::SEV_ERROR, "sinsp above drop treshold %d secs: %" PRIu32 ":%" PRIu32,
				(int)m_configuration->get_drop_upper_threshold(m_machine_info->num_cpus), m_seconds_above_thresholds, 
				m_configuration->get_drop_treshold_consecutive_seconds());
		}
		else
		{
			m_seconds_above_thresholds = 0;
		}

		if(m_seconds_above_thresholds >= m_configuration->get_drop_treshold_consecutive_seconds())
		{
			m_last_system_cpuload = 0;

			for(j = 0; j < m_cpu_loads.size(); j++)
			{
				m_last_system_cpuload += m_cpu_loads[j];
			}

			m_seconds_above_thresholds = 0;

			if(m_sampling_ratio < 128)
			{
				uint32_t new_sampling_ratio;

				if(!m_is_sampling)
				{
					new_sampling_ratio = 1;
					m_is_sampling = true;
				}
				else
				{
					new_sampling_ratio = m_sampling_ratio * 2;
				}

				start_dropping_mode(new_sampling_ratio);
			}
			else
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "sinsp Reached maximum sampling ratio and still too high");
			}
		}

		if(treshold_metric <= (double)m_configuration->get_drop_lower_threshold(m_machine_info->num_cpus))
		{
			m_seconds_below_thresholds++;
	
			if(m_is_sampling && m_sampling_ratio > 1)
			{
				g_logger.format(sinsp_logger::SEV_ERROR, "sinsp below drop treshold %d secs: %" PRIu32 ":%" PRIu32, 
					(int)m_configuration->get_drop_lower_threshold(m_machine_info->num_cpus), m_seconds_below_thresholds, 
					m_configuration->get_drop_treshold_consecutive_seconds());
			}
		}
		else
		{
			m_seconds_below_thresholds = 0;
		}

		if(m_seconds_below_thresholds >= m_configuration->get_drop_treshold_consecutive_seconds() &&
			m_is_sampling)
		{
			double totcpuload = 0;
			bool skip = false;

			for(j = 0; j < m_cpu_loads.size(); j++)
			{
				totcpuload += m_cpu_loads[j];
			}

			if(m_last_system_cpuload != 0)
			{
				if(fabs(totcpuload - m_last_system_cpuload) / min(totcpuload, m_last_system_cpuload) < 0.15)
				{
					if(m_seconds_below_thresholds <= m_configuration->get_drop_treshold_consecutive_seconds() * 50)
					{
						skip = true;
					}
				}
			}

			if(!skip)
			{
				m_last_system_cpuload = 0;

				m_seconds_below_thresholds = 0;
				uint32_t new_sampling_ratio = m_sampling_ratio / 2;

				if(new_sampling_ratio >= 1)
				{
					if(m_is_sampling)
					{
						g_logger.format(sinsp_logger::SEV_ERROR, "sinsp -- Setting drop mode to %" PRIu32, m_sampling_ratio / 2);
						start_dropping_mode(m_sampling_ratio / 2);
					}
					else
					{
						stop_dropping_mode();
					}
				}
			}
		}
	}
}

bool executed_command_cmp(const sinsp_executed_command& src, const sinsp_executed_command& dst)
{
	return (src.m_ts < dst.m_ts); 
}

void sinsp_analyzer::emit_executed_commands()
{
	uint32_t j;
	int32_t last_pipe_head = -1;

	if(m_executed_commands.size() != 0)
	{
		sort(m_executed_commands.begin(),
			m_executed_commands.end(),
			executed_command_cmp);

		//
		// Consolidate command with pipes
		//
		for(j = 0; j < m_executed_commands.size(); j++)
		{
			uint32_t flags = m_executed_commands[j].m_flags;

			if(flags & sinsp_executed_command::FL_PIPE_HEAD)
			{
				last_pipe_head = j;
			}
			else if(flags & (sinsp_executed_command::FL_PIPE_MIDDLE | sinsp_executed_command::FL_PIPE_TAIL))
			{
				if(last_pipe_head != -1)
				{
					m_executed_commands[last_pipe_head].m_cmdline += " | ";
					m_executed_commands[last_pipe_head].m_cmdline += m_executed_commands[j].m_cmdline;
					m_executed_commands[j].m_flags |= sinsp_executed_command::FL_EXCLUDED;
				}
				else
				{
//					ASSERT(false);
				}

				if(flags & sinsp_executed_command::FL_PIPE_TAIL)
				{
					last_pipe_head = -1;
				}
			}
		}

		//
		// If there are too many commands, try to aggregate by command line
		//
		uint32_t cmdcnt = 0;

		vector<sinsp_executed_command>::iterator it;

		for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
		{
			if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;
			}
		}

		if(cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
		{
			map<string, sinsp_executed_command*> cmdlines;

			for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
			{
				if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
				{
					map<string, sinsp_executed_command*>::iterator eit = cmdlines.find(it->m_cmdline);
					if(eit == cmdlines.end())
					{
						cmdlines[it->m_cmdline] = &(*it);
					}
					else
					{
						eit->second->m_count++;
						it->m_flags |= sinsp_executed_command::FL_EXCLUDED;
					}
				}
			}
		}

		//
		// If there are STILL too many commands, try to aggregate by executable
		//
		cmdcnt = 0;

		for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
		{
			if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;
			}
		}

		if(cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
		{
			map<string, sinsp_executed_command*> exes;

			for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
			{
				if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
				{
					map<string, sinsp_executed_command*>::iterator eit = exes.find(it->m_exe);
					if(eit == exes.end())
					{
						exes[it->m_exe] = &(*it);
						it->m_flags |= sinsp_executed_command::FL_EXEONLY;
					}
					else
					{
						eit->second->m_count += it->m_count;
						it->m_flags |= sinsp_executed_command::FL_EXCLUDED;
					}
				}
			}
		}

		cmdcnt = 0;
		for(it = m_executed_commands.begin(); it != m_executed_commands.end(); ++it)
		{
			if(!(it->m_flags & sinsp_executed_command::FL_EXCLUDED))
			{
				cmdcnt++;

				if(cmdcnt > DEFAULT_MAX_EXECUTED_COMMANDS_IN_PROTO)
				{
					break;
				}

				draiosproto::command_details* cd = m_metrics->add_commands();

				cd->set_timestamp(it->m_ts);
				cd->set_exe(it->m_exe);
				if(it->m_parent_comm != "")
				{
					cd->set_parentcomm(it->m_parent_comm);
				}
				cd->set_count(it->m_count);

				if(it->m_flags & sinsp_executed_command::FL_EXEONLY)
				{
					cd->set_cmdline(it->m_comm);
				}
				else
				{
					cd->set_cmdline(it->m_cmdline);
				}
			}
		}
	}
}

void sinsp_analyzer::flush(sinsp_evt* evt, uint64_t ts, bool is_eof, flush_flags flshflags)
{
	uint32_t j;
	uint64_t nevts_in_last_sample;

	if(evt != NULL)
	{
		nevts_in_last_sample = evt->get_num() - m_prev_sample_evtnum;
	}
	else
	{
		nevts_in_last_sample = 0;
	}

	if(flshflags == DF_FORCE_NOFLUSH)
	{
		return;
	}

	if(m_mypid == -1)
	{
		m_mypid = getpid();
	}

	for(j = 0; ; j++)
	{
		if(flshflags == DF_FORCE_FLUSH ||
			flshflags == DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			//
			// Make sure we don't generate too many samples in case of subsampling
			//
			if(j > 0)
			{
				break;
			}
		}
		else
		{
			if(m_next_flush_time_ns > ts)
			{
				break;
			}
		}

		uint64_t sample_duration = m_configuration->get_analyzer_sample_len_ns();

		if(m_next_flush_time_ns == 0)
		{
			//
			// This is the very first event, just initialize the times for future use
			//
			m_next_flush_time_ns = ts - ts % sample_duration + sample_duration;
			m_prev_flush_time_ns = m_next_flush_time_ns - sample_duration;
		}
		else
		{
			m_n_flushes++;

			//
			// Update the times
			//
			m_prev_flush_time_ns = ts - ts % sample_duration;
			m_next_flush_time_ns = m_prev_flush_time_ns + sample_duration;

			ASSERT(m_next_flush_time_ns / sample_duration * sample_duration == m_next_flush_time_ns);
			ASSERT(m_prev_flush_time_ns / sample_duration * sample_duration == m_prev_flush_time_ns);

			//
			// Calculate CPU load
			//
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				m_procfs_parser->get_cpus_load(&m_cpu_loads, &m_cpu_idles, &m_cpu_steals);
			}

			m_total_process_cpu = 0; // this will be calculated when scanning the processes

			//
			// Flush the scheduler analyzer
			//
			m_sched_analyzer2->flush(evt, m_prev_flush_time_ns, is_eof, flshflags);

			if(m_prev_flush_time_ns - m_last_transaction_delays_update_time > TRANSACTION_DELAYS_INTERVAL_NS)
			{
				m_last_transaction_delays_update_time = m_prev_flush_time_ns;
			}

			//
			// Reset the protobuffer
			//
			m_metrics->Clear();

			////////////////////////////////////////////////////////////////////////////
			// EMIT PROCESSES
			////////////////////////////////////////////////////////////////////////////
			emit_processes(evt, sample_duration, is_eof, flshflags);

			////////////////////////////////////////////////////////////////////////////
			// EMIT CONNECTIONS
			////////////////////////////////////////////////////////////////////////////
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, 
					"IPv4 table size:%d",
					m_ipv4_connections->m_connections.size());

				if(m_ipv4_connections->get_n_drops() != 0)
				{
					g_logger.format(sinsp_logger::SEV_ERROR, 
						"IPv4 table drops:%d",
						m_ipv4_connections->get_n_drops());

					m_ipv4_connections->clear_n_drops();
				}
			}

			if(m_configuration->get_aggregate_connections_in_proto())
			{
				//
				// Aggregate external connections and limit the number of entries in the connection table
				//
				emit_aggregated_connections();
			}
			else
			{
				//
				// Emit all the connections
				//
				emit_full_connections();
			}

			//
			// Go though the list of unix connections and for the moment just clean it up
			//
#ifdef HAS_UNIX_CONNECTIONS
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, 
					"unix table size:%d",
					m_unix_connections->m_connections.size());

				if(m_unix_connections->get_n_drops() != 0)
				{
					g_logger.format(sinsp_logger::SEV_ERROR, 
						"IPv4 table size:%d",
						m_unix_connections->m_connections.size());

					m_unix_connections->clear_n_drops();
				}
			}

			unordered_map<unix_tuple, sinsp_connection, unixt_hash, unixt_cmp>::iterator ucit;
			for(ucit = m_unix_connections->m_connections.begin(); 
				ucit != m_unix_connections->m_connections.end();)
			{
				//
				// Has this connection been closed druring this sample?
				//
				if(ucit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					//
					// Yes, remove the connection from the table
					//
					m_unix_connections->m_connections.erase(ucit++);
				}
				else
				{
					++ucit;
				}
			}
#endif // HAS_UNIX_CONNECTIONS

#ifdef HAS_PIPE_CONNECTIONS
			//
			// Go though the list of pipe connections and for the moment just clean it up
			//
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, 
					"pipe table size:%d",
					m_pipe_connections->m_connections.size());
			}

			unordered_map<uint64_t, sinsp_connection, hash<uint64_t>, equal_to<uint64_t>>::iterator pcit;
			for(pcit = m_pipe_connections->m_connections.begin(); 
				pcit != m_pipe_connections->m_connections.end();)
			{
				//
				// Has this connection been closed druring this sample?
				//
				if(pcit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					//
					// Yes, remove the connection from the table
					//
					m_pipe_connections->m_connections.erase(pcit++);
				}
				else
				{
					++pcit;
				}
			}
#endif // HAS_PIPE_CONNECTIONS

			////////////////////////////////////////////////////////////////////////////
			// EMIT THE LIST OF INTERFACES
			////////////////////////////////////////////////////////////////////////////
			vector<sinsp_ipv4_ifinfo>* v4iflist = m_inspector->m_network_interfaces->get_ipv4_list();
			for(uint32_t k = 0; k < v4iflist->size(); k++)
			{
				draiosproto::ipv4_network_interface* ni = m_metrics->add_ipv4_network_interfaces();

				ni->set_name(v4iflist->at(k).m_name);
				ni->set_addr(htonl(v4iflist->at(k).m_addr));
				ni->set_netmask(htonl(v4iflist->at(k).m_netmask));
			}

			////////////////////////////////////////////////////////////////////////////
			// emit host stuff
			////////////////////////////////////////////////////////////////////////////
			m_metrics->set_machine_id(m_configuration->get_machine_id());
			m_metrics->set_customer_id(m_configuration->get_customer_id());
			m_metrics->set_timestamp_ns(m_prev_flush_time_ns);
			m_metrics->set_sampling_ratio(m_sampling_ratio);

			m_metrics->mutable_hostinfo()->set_hostname(sinsp_gethostname());
			m_metrics->mutable_hostinfo()->set_num_cpus(m_machine_info->num_cpus);
			m_metrics->mutable_hostinfo()->set_physical_memory_size_bytes(m_inspector->m_machine_info->memory_size_bytes);

			//
			// Map customizations coming from the analyzer.
			//
			m_metrics->set_host_custom_name(m_configuration->get_host_custom_name());
			m_metrics->set_host_tags(m_configuration->get_host_tags());
			m_metrics->set_is_host_hidden(m_configuration->get_host_hidden());
			m_metrics->set_hidden_processes(m_configuration->get_hidden_processes());
			m_metrics->set_host_custom_map(m_configuration->get_host_custom_map());
			m_metrics->set_version(m_configuration->get_version());
			if(!m_configuration->get_instance_id().empty())
			{
				m_metrics->set_instance_id(m_configuration->get_instance_id());
			}

			ASSERT(m_cpu_loads.size() == 0 || m_cpu_loads.size() == m_machine_info->num_cpus);
			ASSERT(m_cpu_loads.size() == m_cpu_steals.size());
			string cpustr;

			double totcpuload = 0;
			double totcpusteal = 0;

			for(j = 0; j < m_cpu_loads.size(); j++)
			{
				cpustr += to_string((long double) m_cpu_loads[j]) + "(" + to_string((long double) m_cpu_steals[j]) + ") ";
				m_metrics->mutable_hostinfo()->add_cpu_loads((uint32_t)(m_cpu_loads[j] * 100));
				m_metrics->mutable_hostinfo()->add_cpu_steal((uint32_t)(m_cpu_steals[j] * 100));

				totcpuload += m_cpu_loads[j];
				totcpusteal += m_cpu_steals[j];
			}

			ASSERT(totcpuload <= 100 * m_cpu_loads.size());
			ASSERT(totcpusteal <= 100 * m_cpu_loads.size());

			if(totcpuload < m_total_process_cpu)
			{
				totcpuload = m_total_process_cpu;
			}

			if(m_cpu_loads.size() != 0)
			{
				if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG, "CPU:%s", cpustr.c_str());
				}
			}

			int64_t used_memory;
			int64_t used_swap;
			m_procfs_parser->get_global_mem_usage_kb(&used_memory, &used_swap);

			m_host_metrics.m_protostate->to_protobuf(m_metrics->mutable_protos(),
				m_sampling_ratio);

			//
			// host info
			//
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_capacity_score((uint32_t)(m_host_metrics.get_capacity_score() * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(m_host_metrics.get_stolen_score() * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_connection_queue_usage_pct(m_host_metrics.m_connection_queue_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_usage_pct(m_host_metrics.m_fd_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_resident_memory_usage_kb((uint32_t)used_memory);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_swap_memory_usage_kb((uint32_t)used_swap);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_major_pagefaults(m_host_metrics.m_pfmajor);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_minor_pagefaults(m_host_metrics.m_pfminor);
			m_host_metrics.m_syscall_errors.to_protobuf(m_metrics->mutable_hostinfo()->mutable_syscall_errors(), m_sampling_ratio);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_count(m_host_metrics.m_fd_count);

			vector<sinsp_procfs_parser::mounted_fs> fs_list;
			m_procfs_parser->get_mounted_fs_list(&fs_list);
			for(vector<sinsp_procfs_parser::mounted_fs>::const_iterator it = fs_list.begin();
				it != fs_list.end(); ++it)
			{
				draiosproto::mounted_fs* fs = m_metrics->add_mounts();

				fs->set_device(it->device);
				fs->set_mount_dir(it->mount_dir);
				fs->set_type(it->type);
				fs->set_size_bytes(it->size_bytes);
				fs->set_used_bytes(it->used_bytes);
				fs->set_available_bytes(it->available_bytes);
			}

			//
			// Executed commands
			//
			//emit_executed_commands();

			emit_top_files();

			//
			// Transactions
			//
			m_delay_calculator->compute_host_delays(m_host_transaction_delays);

			m_host_transaction_counters.to_protobuf(m_metrics->mutable_hostinfo()->mutable_transaction_counters(),
				m_metrics->mutable_hostinfo()->mutable_min_transaction_counters(),
				m_metrics->mutable_hostinfo()->mutable_max_transaction_counters(), 
				m_sampling_ratio);

			if(m_host_transaction_delays->m_local_processing_delay_ns != -1)
			{
				m_metrics->mutable_hostinfo()->set_transaction_processing_delay(m_host_transaction_delays->m_local_processing_delay_ns * m_sampling_ratio);
				m_metrics->mutable_hostinfo()->set_merged_server_delay(m_host_transaction_delays->m_merged_server_delay * m_sampling_ratio);
				m_metrics->mutable_hostinfo()->set_next_tiers_delay(m_host_transaction_delays->m_merged_client_delay * m_sampling_ratio);
			}

			//
			// Time splits
			//
			m_host_metrics.m_metrics.to_protobuf(m_metrics->mutable_hostinfo()->mutable_tcounters(), m_sampling_ratio);

			m_host_req_metrics.to_reqprotobuf(m_metrics->mutable_hostinfo()->mutable_reqcounters(), m_sampling_ratio);

			m_io_net.to_protobuf(m_metrics->mutable_hostinfo()->mutable_external_io_net(), 1, m_sampling_ratio);
			m_metrics->mutable_hostinfo()->mutable_external_io_net()->set_time_ns_out(0);

			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					"sinsp cpu: %lf", m_my_cpuload);

				g_logger.format(sinsp_logger::SEV_DEBUG,
					"host times: %.2lf%% file:%.2lf%%(in:%" PRIu32 "b/%" PRIu32" out:%" PRIu32 "b/%" PRIu32 ") net:%.2lf%% other:%.2lf%%",
					m_host_metrics.m_metrics.get_processing_percentage() * 100,
					m_host_metrics.m_metrics.get_file_percentage() * 100,
					m_host_metrics.m_metrics.m_tot_io_file.m_bytes_in,
					m_host_metrics.m_metrics.m_tot_io_file.m_count_in,
					m_host_metrics.m_metrics.m_tot_io_file.m_bytes_out,
					m_host_metrics.m_metrics.m_tot_io_file.m_count_out,
					m_host_metrics.m_metrics.get_net_percentage() * 100,
					m_host_metrics.m_metrics.get_other_percentage() * 100);
			}

#ifdef _DEBUG
			double totpct = m_host_metrics.m_metrics.get_processing_percentage() +
				m_host_metrics.m_metrics.get_file_percentage() + 
				m_host_metrics.m_metrics.get_net_percentage() +
				m_host_metrics.m_metrics.get_other_percentage();

			ASSERT(totpct == 0 || (totpct > 0.99 && totpct < 1.01));
#endif // _DEBUG

			if(m_host_transaction_counters.get_counter()->m_count_in + m_host_transaction_counters.get_counter()->m_count_out != 0)
			{
				if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
				{
					g_logger.format(sinsp_logger::SEV_DEBUG,
						" host h:%.2f(s:%.2f)",
						m_host_metrics.get_capacity_score(),
						m_host_metrics.get_stolen_score());

					g_logger.format(sinsp_logger::SEV_DEBUG,
						"  trans)in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
						m_host_transaction_counters.get_counter()->m_count_in * m_sampling_ratio,
						m_host_transaction_counters.get_counter()->m_count_out * m_sampling_ratio,
						(float)m_host_transaction_counters.get_counter()->m_time_ns_in / sample_duration,
						(float)m_client_tr_time_by_servers / sample_duration,
						(m_host_transaction_delays->m_local_processing_delay_ns != -1)?((double)m_host_transaction_delays->m_merged_server_delay) / sample_duration : -1,
						(m_host_transaction_delays->m_local_processing_delay_ns != -1)?((double)m_host_transaction_delays->m_merged_client_delay) / sample_duration : -1,
						(m_host_transaction_delays->m_local_processing_delay_ns != -1)?((double)m_host_transaction_delays->m_local_processing_delay_ns) / sample_duration : -1);

					g_logger.format(sinsp_logger::SEV_DEBUG,
						"host transaction times: proc:%.2lf%% file:%.2lf%% net:%.2lf%% other:%.2lf%%",
						m_host_req_metrics.get_processing_percentage() * 100,
						m_host_req_metrics.get_file_percentage() * 100,
						m_host_req_metrics.get_net_percentage() * 100,
						m_host_req_metrics.get_other_percentage() * 100);
				}
			}

			////////////////////////////////////////////////////////////////////////////
			// Serialize the whole crap
			////////////////////////////////////////////////////////////////////////////
			if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
			{
				uint64_t serialize_sample_time = 
				m_prev_flush_time_ns - m_prev_flush_time_ns % m_configuration->get_analyzer_original_sample_len_ns();

				serialize(evt, serialize_sample_time);
			}

			//
			// Reset the aggregated host metrics
			//
			m_host_metrics.clear();
			m_host_req_metrics.clear();
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// CLEANUPS
	///////////////////////////////////////////////////////////////////////////

	if(m_configuration->get_autodrop_enabled())
	{
		tune_drop_mode(flshflags, m_my_cpuload);
	}

	//
	// Clear the transaction state
	//
	if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, 
			"# Client Transactions:%d",
			m_trans_table->m_n_client_transactions * m_sampling_ratio);
		g_logger.format(sinsp_logger::SEV_DEBUG, 
			"# Server Transactions:%d",
			m_trans_table->m_n_server_transactions * m_sampling_ratio);
	}

	m_trans_table->m_n_client_transactions = 0;
	m_trans_table->m_n_server_transactions = 0;

	m_host_transaction_counters.clear();
	m_client_tr_time_by_servers = 0;

	for(j = 0; j < m_machine_info->num_cpus; j++)
	{
		m_host_server_transactions[j].clear();
		m_host_client_transactions[j].clear();
	}

	//
	// Reset the proc lookup counter
	//
	m_inspector->m_n_proc_lookups = 0;

	//
	// Clear the network I/O counter
	//
	m_io_net.clear();

	//
	// Clear the executed command list
	//
	m_executed_commands.clear();

	//
	// Run the periodic connection and thread table cleanup
	//
	remove_expired_connections(ts);
	m_inspector->m_thread_manager->remove_inactive_threads();
	
	if(evt)
	{
		if(flshflags != DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "----- %" PRIu64 "", nevts_in_last_sample);
		}

		m_prev_sample_evtnum = evt->get_num();

		//
		// This thread might be removed, either by a procexit or by thread table
		// cleanup process
		// In either case, evt->m_tinfo would become invalid.
		// To avoid that, we refresh evt->m_tinfo.
		//
		evt->m_tinfo = NULL;	// This is important to avoid using a stale cached value!
		evt->m_tinfo = evt->get_thread_info();
	}
}

//
// Parses a previous select/poll/epoll and account its time based on the successive I/O operation
//
void sinsp_analyzer::add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat)
{
	thread_analyzer_info* tainfo = evt->m_tinfo->m_ainfo;
	int64_t wd = evt->m_tinfo->m_ainfo->m_last_wait_duration_ns;

	ASSERT(tainfo != NULL);

	if(wd != 0)
	{
		uint64_t we = tainfo->m_last_wait_end_time_ns;

		if(we >= m_prev_flush_time_ns)
		{
			uint64_t ws;
			uint64_t delta;

			if(wd > 0)
			{
				ws = we - wd; 
			}
			else
			{
				ws = we + wd; 
			}

			delta = we - MAX(ws, m_prev_flush_time_ns);

			sinsp_counters* metrics = &tainfo->m_metrics;

			//
			// This can happen in case of event drops
			//
			if(delta > metrics->m_wait_other.m_time_ns)
			{
				tainfo->m_last_wait_duration_ns = 0;
				tainfo->m_last_wait_end_time_ns = 0;
				return;
			}

			if(cat->m_category == EC_FILE)
			{
				metrics->m_wait_file.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else if(cat->m_category == EC_NET)
			{
				metrics->m_wait_net.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else if(cat->m_category == EC_IPC)
			{
				metrics->m_wait_ipc.add_other(1, delta);
				metrics->m_wait_other.subtract(1, delta);
			}
			else
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_NET:
					if(cat->m_category == EC_IO_READ)
					{
						break;
					}
					else if(cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_net.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_net.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				case sinsp_evt::SC_FILE:
					if(cat->m_category == EC_IO_READ)
					{
						metrics->m_wait_file.add_in(1, delta);
					}
					else if(cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_file.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_file.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				case sinsp_evt::SC_IPC:
					if(cat->m_category == EC_IO_READ)
					{
						metrics->m_wait_ipc.add_in(1, delta);
					}
					else if(cat->m_category == EC_IO_WRITE)
					{
						metrics->m_wait_ipc.add_out(1, delta);
					}
					else
					{
						metrics->m_wait_ipc.add_other(1, delta);
					}

					metrics->m_wait_other.subtract(1, delta);
					break;
				default:
					break;
				}
			}
		}

		tainfo->m_last_wait_duration_ns = 0;
		tainfo->m_last_wait_end_time_ns = 0;
	}
}

//
// Analyzer event processing entry point
//
void sinsp_analyzer::process_event(sinsp_evt* evt, flush_flags flshflags)
{
	uint64_t ts;
	uint64_t delta;
	sinsp_evt::category cat;
	uint16_t etype;
	thread_analyzer_info* tainfo;

	//
	// If there is no event, assume that this is an EOF and use the 
	// next sample event as target time
	//
	if(evt)
	{
		ts = evt->get_ts();
		etype = evt->get_type();

		if(m_parser->process_event(evt) == false)
		{
			return;
		}
	}
	else
	{
		if(m_sampling_ratio == 1)
		{
			ts = m_next_flush_time_ns;
			flush(evt, ts, true, flshflags);
			return;
		}
		else
		{
			return;
		}
	}

	//
	// Check if it's time to flush
	//
	if(ts >= m_next_flush_time_ns)
	{
		bool do_flush = true;

		if(m_sampling_ratio != 1)
		{
			do_flush = false;
		}

		if(do_flush)
		{
			flush(evt, ts, false, flshflags);
		}
	}

	//
	// This is where normal event parsing starts.
	// The following code is executed for every event
	//
	if(evt->m_tinfo == NULL || 
		etype == PPME_SCHEDSWITCH_1_E ||
		etype == PPME_SCHEDSWITCH_6_E)
	{
		//
		// No thread associated to this event, nothing to do
		//
		return;
	}

	tainfo = evt->m_tinfo->m_ainfo;

	if(tainfo == NULL)
	{
		//
		// No analyzer state associated to this thread.
		// This should never happen. If it does, skip the event.
		//
		ASSERT(false);
		return;
	}

	//
	// Get the event category and type
	//
	evt->get_category(&cat);

	//
	// For our purposes, accept() is wait, not networking
	//
	if(etype == PPME_SOCKET_ACCEPT_E || etype == PPME_SOCKET_ACCEPT_X)
	{
		cat.m_category = EC_WAIT;
	}

	//
	// Check if this is an event that goes across sample boundaries
	//
	if((tainfo->m_th_analysis_flags & thread_analyzer_info::AF_PARTIAL_METRIC) != 0)
	{
		//
		// Part of this event has already been attributed to the previous sample, 
		// we just include the remaining part
		//
		tainfo->m_th_analysis_flags &= ~(thread_analyzer_info::AF_PARTIAL_METRIC);

		delta = ts - m_prev_flush_time_ns;
	}
	else
	{
		//
		// Normal event that falls completely inside this sample
		//
		delta = ts - evt->m_tinfo->m_lastevent_ts;
	}

	//
	// Add this event time to the right category in the metrics array
	//
	if(PPME_IS_ENTER(etype))
	{
		//
		// remember the category in the thread info. We'll use 
		// it if we need to flush the sample.
		//
		evt->m_tinfo->m_lastevent_category = cat;

		//
		// Switch the category to processing
		//
		cat.m_category = EC_PROCESSING;
	}
	else
	{
		if(!evt->m_tinfo->is_lastevent_data_valid())
		{
			//
			// There was some kind of drop and the enter event is not matching
			//
			cat.m_category = EC_UNKNOWN;
		}

		//
		// If a sample flush happens after this event, the time will have to
		// be attributed to processing.
		//
		evt->m_tinfo->m_lastevent_category.m_category = EC_PROCESSING;

		//
		// If this is an fd-based syscall that comes after a wait, update the wait time
		//
		ppm_event_flags eflags = evt->get_flags();
		if(eflags & EF_USES_FD)
		{
			add_wait_time(evt, &cat);
		}
	}

	//
	// Increase the counter
	//
	bool do_inc_counter = (cat.m_category != EC_PROCESSING);

	add_syscall_time(&tainfo->m_metrics, 
		&cat,
		delta, 
		evt->get_iosize(),
		do_inc_counter);

	//
	// If this is an error syscall, add the error to the process and host table
	//
	if(evt->m_errorcode != 0)
	{
		if((evt->m_errorcode != SE_EINPROGRESS) && 
			(evt->m_errorcode != SE_EAGAIN) && 
			(evt->m_errorcode != SE_ETIMEDOUT))
		{
			m_host_metrics.m_syscall_errors.add(evt);
			
			ASSERT(evt->m_tinfo);
			ASSERT(evt->m_tinfo->m_ainfo);

			evt->m_tinfo->m_ainfo->m_dynstate->m_syscall_errors.add(evt);
		}
	}
}

void sinsp_analyzer::add_syscall_time(sinsp_counters* metrics, 
									  sinsp_evt::category* cat, 
									  uint64_t delta, 
									  uint32_t bytes, 
									  bool inc_count)
{
	uint32_t cnt_delta = (inc_count)? 1 : 0;

	switch(cat->m_category)
	{
		case EC_UNKNOWN:
			metrics->m_unknown.add(cnt_delta, delta);
			break;
		case EC_OTHER:
			metrics->m_other.add(cnt_delta, delta);
			break;
		case EC_FILE:
			metrics->m_file.add(cnt_delta, delta);
			break;
		case EC_NET:
			metrics->m_net.add(cnt_delta, delta);
			break;
		case EC_IPC:
			metrics->m_ipc.add(cnt_delta, delta);
			break;
		case EC_MEMORY:
			metrics->m_memory.add(cnt_delta, delta);
			break;
		case EC_PROCESS:
			metrics->m_process.add(cnt_delta, delta);
			break;
		case EC_SLEEP:
			metrics->m_sleep.add(cnt_delta, delta);
			break;
		case EC_SYSTEM:
			metrics->m_system.add(cnt_delta, delta);
			break;
		case EC_SIGNAL:
			metrics->m_signal.add(cnt_delta, delta);
			break;
		case EC_USER:
			metrics->m_user.add(cnt_delta, delta);
			break;
		case EC_TIME:
			metrics->m_time.add(cnt_delta, delta);
			break;
		case EC_PROCESSING:
			metrics->m_processing.add(cnt_delta, delta);
			break;
		case EC_IO_READ:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add_in(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add_in(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add_in(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add_in(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add_in(cnt_delta, delta, bytes);
					break;
				}
			}
			break;
		case EC_IO_WRITE:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add_out(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add_out(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add_out(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add_out(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add_out(cnt_delta, delta, bytes);
					break;
				}
			}
			break;
		case EC_IO_OTHER:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add_other(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add_other(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add_other(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add_other(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add_other(cnt_delta, delta, bytes);
					break;
				}
			}
			break;
		case EC_WAIT:
			metrics->m_wait_other.add(cnt_delta, delta);
			break;
		case EC_SCHEDULER:
			break;
		default:
			ASSERT(false);
	}
}

void sinsp_analyzer::emit_top_files()
{
	vector<analyzer_file_stat*> files_sortable_list;

	for(unordered_map<string, analyzer_file_stat>::iterator it = m_fd_listener->m_files_stat.begin();
		it != m_fd_listener->m_files_stat.end(); ++it)
	{
		files_sortable_list.push_back(&it->second);
	}

	if(files_sortable_list.size() > TOP_FILES_IN_SAMPLE)
	{
		partial_sort(files_sortable_list.begin(), 
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE, 
			files_sortable_list.end(),
			analyzer_file_stat::cmp_bytes);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}

		partial_sort(files_sortable_list.begin(), 
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE, 
			files_sortable_list.end(),
			analyzer_file_stat::cmp_time);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}

		partial_sort(files_sortable_list.begin(), 
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE, 
			files_sortable_list.end(),
			analyzer_file_stat::cmp_errors);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}

		partial_sort(files_sortable_list.begin(), 
			files_sortable_list.begin() + TOP_FILES_IN_SAMPLE, 
			files_sortable_list.end(),
			analyzer_file_stat::cmp_open_count);

		for(uint32_t j = 0; j < TOP_FILES_IN_SAMPLE; j++)
		{
			files_sortable_list[j]->m_exclude_from_sample = false;
		}
	}
	else
	{
		for(vector<analyzer_file_stat*>::const_iterator it = files_sortable_list.begin();
			it != files_sortable_list.end(); ++it)
		{
			(*it)->m_exclude_from_sample = false;
		}
	}

	for(vector<analyzer_file_stat*>::const_iterator it = files_sortable_list.begin();
		it != files_sortable_list.end(); ++it)
	{
		if((*it)->m_exclude_from_sample == false)
		{
			draiosproto::file_stat* top_file = m_metrics->add_top_files();

			top_file->set_name((*it)->m_name);
			top_file->set_bytes((*it)->m_bytes);
			top_file->set_time_ns((*it)->m_time_ns);
			top_file->set_open_count((*it)->m_open_count);
			top_file->set_errors((*it)->m_errors);
		}
	}

	m_fd_listener->m_files_stat.clear();
}

#define MR_UPDATE_POS { if(len == -1) return -1; pos += len;}

int32_t sinsp_analyzer::generate_memory_report(OUT char* reportbuf, uint32_t reportbuflen, bool do_complete_report)
{
	int len;
	uint32_t pos = 0;
	uint32_t nfds = 0;
	uint32_t nfds_file = 0;
	uint32_t nfds_ipv4 = 0;
	uint32_t nfds_ipv6 = 0;
	uint32_t nfds_dir = 0;
	uint32_t nfds_ipv4s = 0;
	uint32_t nfds_ipv6s = 0;
	uint32_t nfds_fifo = 0;
	uint32_t nfds_unix = 0;
	uint32_t nfds_event = 0;
	uint32_t nfds_unknown = 0;
	uint32_t nfds_unsupported = 0;
	uint32_t nfds_signal = 0;
	uint32_t nfds_evtpoll = 0;
	uint32_t nfds_inotify = 0;
	uint32_t nfds_timerfd = 0;
	uint32_t ntransactions = 0;
	uint32_t ntransactions_http = 0;
	uint32_t ntransactions_mysql = 0;
	uint32_t nqueuedtransactions_client = 0;
	uint32_t nqueuedtransactions_server = 0;
	uint32_t nqueuedtransactions_client_capacity = 0;
	uint32_t nqueuedtransactions_server_capacity = 0;

	len = snprintf(reportbuf + pos, reportbuflen - pos, 
		"threads: %d\n", (int)m_inspector->m_thread_manager->m_threadtable.size());
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"connections: %d\n", (int)m_ipv4_connections->size());
	MR_UPDATE_POS;

	for(auto it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); ++it)
	{
		thread_analyzer_info* ainfo = it->second.m_ainfo;

		for(uint32_t j = 0; j < ainfo->m_dynstate->m_server_transactions_per_cpu.size(); j++)
		{
			nqueuedtransactions_server += ainfo->m_dynstate->m_server_transactions_per_cpu[j].size();
			nqueuedtransactions_server_capacity += 
				ainfo->m_dynstate->m_server_transactions_per_cpu[j].capacity();
		}

		for(uint32_t j = 0; j < ainfo->m_dynstate->m_client_transactions_per_cpu.size(); j++)
		{
			nqueuedtransactions_client += ainfo->m_dynstate->m_client_transactions_per_cpu[j].size();
			nqueuedtransactions_client_capacity += 
				ainfo->m_dynstate->m_client_transactions_per_cpu[j].capacity();
		}

		if(do_complete_report)
		{
			len =  snprintf(reportbuf + pos, reportbuflen - pos, 
				"    tid: %d comm: %s nfds:%d\n", (int)it->first, it->second.m_comm.c_str(), (int)it->second.m_fdtable.size());
			MR_UPDATE_POS;
		}

		for(auto fdit = it->second.m_fdtable.m_table.begin(); 
			fdit != it->second.m_fdtable.m_table.end(); ++fdit)
		{
			nfds++;

			switch(fdit->second.m_type)
			{
				case SCAP_FD_FILE:
					nfds_file++;
					break;
				case SCAP_FD_IPV4_SOCK:
					nfds_ipv4++;
					break;
				case SCAP_FD_IPV6_SOCK:
					nfds_ipv6++;
					break;
				case SCAP_FD_DIRECTORY:
					nfds_dir++;
					break;
				case SCAP_FD_IPV4_SERVSOCK:
					nfds_ipv4s++;
					break;
				case SCAP_FD_IPV6_SERVSOCK:
					nfds_ipv6s++;
					break;
				case SCAP_FD_FIFO:
					nfds_fifo++;
					break;
				case SCAP_FD_UNIX_SOCK:
					nfds_unix++;
					break;
				case SCAP_FD_EVENT:
					nfds_event++;
					break;
				case SCAP_FD_UNKNOWN:
					nfds_unknown++;
					break;
				case SCAP_FD_UNSUPPORTED:
					nfds_unsupported++;
					break;
				case SCAP_FD_SIGNALFD:
					nfds_signal++;
					break;
				case SCAP_FD_EVENTPOLL:
					nfds_evtpoll++;
					break;
				case SCAP_FD_INOTIFY:
					nfds_inotify++;
					break;
				case SCAP_FD_TIMERFD:
					nfds_timerfd++;
					break;
				default:
					nfds_unknown++;
			}

			if(fdit->second.is_transaction())
			{
				ntransactions++;

				if(fdit->second.m_usrstate != NULL)
				{
					if(fdit->second.m_usrstate->m_protoparser != NULL)
					{
						switch(fdit->second.m_usrstate->m_protoparser->get_type())
						{
						case sinsp_protocol_parser::PROTO_HTTP:
							ntransactions_http++;
							break;
						case sinsp_protocol_parser::PROTO_MYSQL:
							ntransactions_mysql++;
							break;
						default:
							ASSERT(false);
							break;
						}
					}
				}
			}
		}
	}

	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"FDs: %d\n", (int)nfds);
	MR_UPDATE_POS;

	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  ipv4: %d\n", (int)nfds_ipv4);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  ipv6: %d\n", (int)nfds_ipv6);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  dir: %d\n", (int)nfds_dir);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  ipv4s: %d\n", (int)nfds_ipv4s);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  ipv6s: %d\n", (int)nfds_ipv6s);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  fifo: %d\n", (int)nfds_fifo);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  unix: %d\n", (int)nfds_unix);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  event: %d\n", (int)nfds_event);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  file: %d\n", (int)nfds_file);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  unknown: %d\n", (int)nfds_unknown);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  unsupported: %d\n", (int)nfds_unsupported);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  signal: %d\n", (int)nfds_signal);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  evtpoll: %d\n", (int)nfds_evtpoll);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  inotify: %d\n", (int)nfds_inotify);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  timerfd: %d\n", (int)nfds_timerfd);
	MR_UPDATE_POS;

	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"transactions: %d\n", (int)ntransactions);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  http: %d\n", (int)ntransactions_http);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  mysql: %d\n", (int)ntransactions_mysql);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  queued client: %d\n", (int)nqueuedtransactions_client);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  queued server: %d\n", (int)nqueuedtransactions_server);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  queue client capacity: %d\n", (int)nqueuedtransactions_client_capacity);
	MR_UPDATE_POS;
	len =  snprintf(reportbuf + pos, reportbuflen - pos, 
		"  queue server capacity: %d\n", (int)nqueuedtransactions_server_capacity);
	MR_UPDATE_POS;

	//fprintf(stdout, "%s", reportbuf);
	return pos;
}

void sinsp_analyzer::set_autodrop_enabled(bool enabled)
{
	m_configuration->set_autodrop_enabled(enabled);
	m_seconds_above_thresholds = 0;
	m_seconds_below_thresholds = 0;
}

void sinsp_analyzer::stop_dropping_mode()
{
	m_inspector->stop_dropping_mode();
	m_driver_stopped_dropping = false;
}

void sinsp_analyzer::start_dropping_mode(uint32_t sampling_ratio)
{
	m_inspector->start_dropping_mode(sampling_ratio);
}

bool sinsp_analyzer::driver_stopped_dropping()
{
	return m_driver_stopped_dropping;
}

#endif // HAS_ANALYZER
