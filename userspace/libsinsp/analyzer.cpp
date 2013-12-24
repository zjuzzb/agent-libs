#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <endian.h>
#endif // _WIN32
#include <google/protobuf/io/coded_stream.h>
#ifndef _WIN32
#include <google/protobuf/io/gzip_stream.h>
#endif
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using namespace google::protobuf::io;

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "parsers.h"
#include "connectinfo.h"
#include "metrics.h"
#include "analyzer.h"
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "proto_header.h"

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
	m_prev_sample_evtnum = 0;
	m_client_tr_time_by_servers = 0;

	//
	// Initialize the CPU calculation counters
	//
	m_machine_info = m_inspector->get_machine_info();
	if(m_machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("machine infor missing, analyzer can't start");
	}

	m_procfs_parser = new sinsp_procfs_parser(m_machine_info->num_cpus, m_machine_info->memory_size_bytes / 1024, m_inspector->m_islive);
	m_procfs_parser->get_global_cpu_load(&m_old_global_total_jiffies);

	m_sched_analyzer2 = new sinsp_sched_analyzer2(inspector, m_machine_info->num_cpus);
	m_score_calculator = new sinsp_scores(inspector, m_sched_analyzer2);
	m_delay_calculator = new sinsp_delays(this, m_machine_info->num_cpus);

	m_host_server_transactions = vector<vector<sinsp_trlist_entry>>(m_machine_info->num_cpus);
	m_host_client_transactions = vector<vector<sinsp_trlist_entry>>(m_machine_info->num_cpus);
	m_last_transaction_delays_update_time = 0;
	m_total_process_cpu = 0;

	m_host_transaction_delays = new sinsp_delays_info();

	inspector->reserve_thread_memory(sizeof(thread_analyzer_info));
}

sinsp_analyzer::~sinsp_analyzer()
{
	if(m_metrics)
	{
		delete m_metrics;
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
}

void sinsp_analyzer::on_capture_start()
{
	ASSERT(m_sched_analyzer2 != NULL);
	m_sched_analyzer2->on_capture_start();
}

void sinsp_analyzer::set_sample_callback(analyzer_callback_interface* cb)
{
	ASSERT(cb != NULL);
	ASSERT(m_sample_callback == NULL);
	m_sample_callback = cb;
}

char* sinsp_analyzer::serialize_to_bytebuf(OUT uint32_t *len, bool compressed)
{
	//
	// Find out how many bytes we need for the serialization
	//
	uint32_t tlen = m_metrics->ByteSize();
	
    //
    // We allocate 4 additional bytes for the buffer lenght
    //
    uint32_t full_len = tlen + sizeof(sinsp_sample_header);
		
    //
    // If the buffer is not big enough, expand it
    //
    if(m_serialization_buffer_size < (full_len))
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
        ArrayOutputStream array_output(m_serialization_buffer + sizeof(sinsp_sample_header), tlen);
        GzipOutputStream gzip_output(&array_output);

        m_metrics->SerializeToZeroCopyStream(&gzip_output);
        gzip_output.Close();

        uint32_t compressed_size = (uint32_t)array_output.ByteCount();
        if(compressed_size > tlen)
        {
            ASSERT(false);
            char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "unexpected serialization buffer size");
            throw sinsp_exception(estr);
        }

        *len = compressed_size;
        return m_serialization_buffer + sizeof(sinsp_sample_header);
#endif
	}
	else
	{
		//
		// Reserve 4 bytes at the beginning of the string for the length
		//
		ArrayOutputStream array_output(m_serialization_buffer + sizeof(sinsp_sample_header), tlen);
		m_metrics->SerializeToZeroCopyStream(&array_output);

        *len = tlen;
        return m_serialization_buffer + sizeof(sinsp_sample_header);
	}
}

void sinsp_analyzer::serialize(uint64_t ts)
{
	char fname[128];
	uint32_t buflen;

	//
	// Serialize to a memory buffer
	//
	char* buf = sinsp_analyzer::serialize_to_bytebuf(&buflen,
		m_inspector->m_configuration.get_compress_metrics());

	g_logger.format(sinsp_logger::SEV_INFO,
		"serialization info: ts=%" PRIu64 ", len=%" PRIu32,
		ts / 1000000000,
		buflen);

	if(!buf)
	{
		return;
	}

	//
	// If we have a callback, invoke it with the data
	//
	if(m_sample_callback != NULL)
	{
		sinsp_sample_header* hdr = (sinsp_sample_header*)(buf - sizeof(sinsp_sample_header));

		hdr->m_sample_len = buflen + sizeof(sinsp_sample_header);
		hdr->m_version = PROTOCOL_VERSION_NUMBER;
		hdr->m_messagetype = PROTOCOL_MESSAGE_TYPE_NUMBER;

		m_sample_callback->sinsp_analyzer_data_ready(ts, (char*)hdr);
	}

	//
	// Write the data to file
	//
	if(m_inspector->m_configuration.get_emit_metrics_to_file())
	{
		snprintf(fname, sizeof(fname), "%s%" PRIu64 ".dam",
			m_inspector->m_configuration.get_metrics_directory().c_str(),
			ts / 1000000000);
		FILE* fp = fopen(fname, "wb");

		if(!fp)
		{
			char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't open file %s", fname);
			throw sinsp_exception(estr);
		}
/*
		// first there's a 32bit frame length...
		uint32_t nbo_frame_length = htonl(buflen);
		if(fwrite(&nbo_frame_length, sizeof(nbo_frame_length), 1, fp) != 1)
		{
			ASSERT(false);
			char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't write frame length to file %s", fname);
			throw sinsp_exception(estr);
		}
*/
		// ..and then there's the actual data
		if(fwrite(buf, buflen, 1, fp) != 1)
		{
			ASSERT(false);
			char *estr = g_logger.format(sinsp_logger::SEV_ERROR, "can't write actual data to file %s", fname);
			throw sinsp_exception(estr);
		}

		fclose(fp);
	}
}

void sinsp_analyzer::emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof)
{
	uint64_t delta;
	sinsp_evt::category* cat;
	sinsp_evt::category tcat;
	m_server_programs.clear();

	g_logger.format(sinsp_logger::SEV_DEBUG, 
		"thread table size:%d",
		m_inspector->m_thread_manager->get_thread_count());

	if(m_inspector->m_ipv4_connections->get_n_drops() != 0)
	{
		g_logger.format(sinsp_logger::SEV_ERROR, 
			"IPv4 table size:%d",
			m_inspector->m_ipv4_connections->m_connections.size());

		m_inspector->m_ipv4_connections->clear_n_drops();
	}

	//
	// Extract global CPU info
	//
	uint64_t cur_global_total_jiffies;
	if(m_inspector->m_islive)
	{
		m_procfs_parser->get_global_cpu_load(&cur_global_total_jiffies);
	}
	else
	{
		cur_global_total_jiffies = 0;
	}

	///////////////////////////////////////////////////////////////////////////
	// First pass of the list of threads: emit the metrics (if defined)
	// and aggregate them into processes
	///////////////////////////////////////////////////////////////////////////
	threadinfo_map_iterator_t it;
	for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); ++it)
	{
		//
		// Attribute the last pending event to this second
		//
		if(m_prev_flush_time_ns != 0)
		{
			delta = m_prev_flush_time_ns - it->second.m_lastevent_ts;
			it->second.m_lastevent_ts = m_prev_flush_time_ns;

			if(delta > sample_duration)
			{
				delta = sample_duration;
			}

			if(PPME_IS_ENTER(it->second.m_lastevent_type))
			{
				cat = &it->second.m_lastevent_category;
			}
			else
			{
				tcat.m_category = EC_PROCESSING;
				tcat.m_subcategory = sinsp_evt::SC_NONE;
				cat = &tcat;
			}

			add_syscall_time(&it->second.m_ainfo->m_metrics, 
				cat, 
				delta,
				0,
				false);

			//
			// Flag the thread so we know that part of this event has already been attributed
			//
			it->second.m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_PARTIAL_METRIC;
		}

		//
		// Some assertions to validate that everything looks like expected
		//
#ifdef _DEBUG
		sinsp_counter_time ttot;
		it->second.m_ainfo->m_metrics.get_total(&ttot);
		ASSERT(is_eof || ttot.m_time_ns % sample_duration == 0);
#endif

		//
		// Go through the FD list to flush the transactions that haven't been active for a while
		//
		it->second.m_ainfo->flush_inactive_transactions(m_prev_flush_time_ns, sample_duration);

		//
		// If this is a process, compute CPU load and memory usage
		//
		it->second.m_ainfo->m_cpuload = 0;

		if(it->second.is_main_thread())
		{
			if(m_inspector->m_islive)
			{
				it->second.m_ainfo->m_cpuload = m_procfs_parser->get_process_cpu_load_and_mem(it->second.m_pid, 
					&it->second.m_ainfo->m_old_proc_jiffies, 
					cur_global_total_jiffies - m_old_global_total_jiffies,
					&it->second.m_ainfo->m_resident_memory_kb);

				m_total_process_cpu += it->second.m_ainfo->m_cpuload;
			}
		}

		//
		// Add this thread's counters to the process ones...
		//
#ifdef ANALYZER_EMITS_PROGRAMS
		sinsp_threadinfo* mtinfo = it->second.get_main_program_thread();
#else
		sinsp_threadinfo* mtinfo = it->second.get_main_thread();
#endif
		mtinfo->m_ainfo->add_all_metrics(it->second.m_ainfo);

		//
		// ... And to the host ones
		//
		m_host_transaction_counters.add(&it->second.m_ainfo->m_external_transaction_metrics);

		if(mtinfo->m_ainfo->m_procinfo->m_proc_transaction_metrics.m_counter.m_count_in != 0)
		{
			m_server_programs.insert(mtinfo->m_tid);
			m_client_tr_time_by_servers += it->second.m_ainfo->m_external_transaction_metrics.m_counter.m_time_ns_out;
		}

#ifdef ANALYZER_EMITS_THREADS
		//
		// Dump the thread info into the protobuf
		//
		sinsp_counter_time tot;
		it->second.m_metrics.get_total(&tot);
		ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);

		if(tot.m_count != 0)
		{
			draiosproto::thread* thread = m_metrics->add_threads();
			thread->set_pid(it->second.m_pid);
			thread->set_tid(it->second.m_tid);
			// CWD is currently disabed in the protocol
			//thread->set_cwd(it->second.m_cwd);
			it->second.m_metrics.to_protobuf(thread->mutable_tcounters());
			it->second.m_transaction_metrics.to_protobuf(thread->mutable_transaction_counters());
		}
#endif
	}


	///////////////////////////////////////////////////////////////////////////
	// Second pass of the list of threads: aggreagate threads into processes 
	// or programs.
	///////////////////////////////////////////////////////////////////////////
	m_host_metrics.m_capacity_score = -1;

	for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); 
		)
	{
		//
		// If this is the main thread of a process, add an entry into the processes
		// section too
		//
#ifdef ANALYZER_EMITS_PROGRAMS
		if(it->second.is_main_program_thread())
#else
		if(it->second.is_main_thread())
#endif
		{
			int64_t pid = it->second.m_pid;
			sinsp_procinfo* procinfo = it->second.m_ainfo->m_procinfo;

#ifdef ANALYZER_EMITS_PROCESSES
			sinsp_counter_time tot;
	
			ASSERT(procinfo != NULL);

			procinfo->m_proc_metrics.get_total(&tot);
			ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);

			if(tot.m_count != 0 || procinfo->m_cpuload != 0 ||
				it->second.m_ainfo->m_th_analysis_flags & (thread_analyzer_info::AF_IS_IPV4_SERVER | thread_analyzer_info::AF_IS_UNIX_SERVER | 
				thread_analyzer_info::AF_IS_IPV4_CLIENT | thread_analyzer_info::AF_IS_UNIX_CLIENT))
			{
#ifdef ANALYZER_EMITS_PROGRAMS
				draiosproto::program* prog = m_metrics->add_programs();
				draiosproto::process* proc = prog->mutable_procinfo();

				vector<int64_t>* pids = &procinfo->m_program_pids;
				for(uint32_t jj = 0; jj < pids->size(); jj++)
				{
					prog->add_pids((*pids)[jj]);
				}
#else // ANALYZER_EMITS_PROGRAMS
				draiosproto::process* proc = m_metrics->add_processes();
#endif // ANALYZER_EMITS_PROGRAMS

				//
				// Basic values
				//
				proc->set_pid(pid);

				if((it->second.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_INCLUDE_INFO_IN_PROTO) ||
					(m_n_flushes % PROCINFO_IN_SAMPLE_INTERVAL == (PROCINFO_IN_SAMPLE_INTERVAL - 1)))
				{
					proc->mutable_details()->set_comm(it->second.m_comm);
					proc->mutable_details()->set_exe(it->second.m_exe);
					for(vector<string>::const_iterator arg_it = it->second.m_args.begin(); 
						arg_it != it->second.m_args.end(); ++arg_it)
					{
						proc->mutable_details()->add_args(*arg_it);
					}

					it->second.m_ainfo->m_th_analysis_flags &= ~thread_analyzer_info::AF_INCLUDE_INFO_IN_PROTO;
				}

				if(it->second.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_IPV4_SERVER)
				{
					proc->set_is_ipv4_transaction_server(true);
				}
				else if(it->second.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_SERVER)
				{
					proc->set_is_unix_transaction_server(true);
				}

				if(it->second.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_IPV4_CLIENT)
				{
					proc->set_is_ipv4_transaction_client(true);
				}
				else if(it->second.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_CLIENT)
				{
					proc->set_is_unix_transaction_client(true);
				}

				if(procinfo->m_cpuload != -1)
				{
					if(procinfo->m_cpuload > (int32_t)(100 * m_machine_info->num_cpus))
					{
						procinfo->m_cpuload = (int32_t)100 * m_machine_info->num_cpus;
					}

					proc->mutable_resource_counters()->set_cpu_pct(procinfo->m_cpuload * 100);
					proc->mutable_resource_counters()->set_resident_memory_usage_kb(procinfo->m_resident_memory_kb);
				}
				else
				{
					proc->mutable_resource_counters()->set_cpu_pct(0);
					proc->mutable_resource_counters()->set_resident_memory_usage_kb(0);
				}

				if(tot.m_count != 0)
				{
					sinsp_delays_info* prog_delays = &procinfo->m_transaction_delays;
					m_delay_calculator->compute_program_delays(&it->second, prog_delays);

					//
					// Transaction-related metrics
					//
					if(prog_delays->m_local_processing_delay_ns != -1)
					{
						procinfo->m_proc_transaction_processing_delay_ns = prog_delays->m_local_processing_delay_ns;
					}
					procinfo->m_proc_metrics.to_protobuf(proc->mutable_tcounters(), sample_duration);
					procinfo->m_proc_transaction_metrics.to_protobuf(proc->mutable_transaction_counters());
					proc->set_transaction_processing_delay(procinfo->m_proc_transaction_processing_delay_ns);

					//
					// Health-related metrics
					//
					if(procinfo->m_proc_transaction_metrics.m_counter.m_count_in != 0)
					{
						sinsp_score_info scores = m_score_calculator->get_process_capacity_score(&it->second,
							prog_delays,
#ifdef ANALYZER_EMITS_PROGRAMS
							procinfo->m_program_pids.size(),
#else
							(uint32_t)it->second.m_nchilds,
#endif
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
						if(procinfo->m_capacity_score > m_host_metrics.m_capacity_score)
						{
							m_host_metrics.m_capacity_score = procinfo->m_capacity_score;
							m_host_metrics.m_stolen_capacity_score = procinfo->m_stolen_capacity_score;
						}
					}

					proc->mutable_resource_counters()->set_capacity_score((uint32_t)(procinfo->m_capacity_score * 100));
					proc->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(procinfo->m_stolen_capacity_score * 100));
					proc->mutable_resource_counters()->set_connection_queue_usage_pct(procinfo->m_connection_queue_usage_pct);
					proc->mutable_resource_counters()->set_fd_usage_pct(procinfo->m_fd_usage_pct);

					//
					// Error-related metrics
					//
					procinfo->m_syscall_errors.to_protobuf(proc->mutable_syscall_errors());

#if 1
					if(procinfo->m_proc_transaction_metrics.m_counter.m_count_in != 0)
					{
						uint64_t trtimein = procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_in;
						uint64_t trtimeout = procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_out;
						uint32_t trcountin = procinfo->m_proc_transaction_metrics.m_counter.m_count_in;
						uint32_t trcountout = procinfo->m_proc_transaction_metrics.m_counter.m_count_out;

						g_logger.format(sinsp_logger::SEV_DEBUG,
							" %s (%" PRIu64 ")%" PRIu64 " h:%.2f(s:%.2f) cpu:%.2f %%f:%" PRIu32 " %%c:%" PRIu32,
							it->second.m_comm.c_str(),
							it->second.m_tid,
							it->second.m_nchilds + 1,
							procinfo->m_capacity_score,
							procinfo->m_stolen_capacity_score,
							(float)procinfo->m_cpuload,
							procinfo->m_fd_usage_pct,
							procinfo->m_connection_queue_usage_pct);

						g_logger.format(sinsp_logger::SEV_DEBUG,
							"  trans)in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
							procinfo->m_proc_transaction_metrics.m_counter.m_count_in,
							procinfo->m_proc_transaction_metrics.m_counter.m_count_out,
							trcountin? ((double)trtimein) / sample_duration : 0,
							trcountout? ((double)trtimeout) / sample_duration : 0,
							(prog_delays)?((double)prog_delays->m_merged_server_delay) / sample_duration : 0,
							(prog_delays)?((double)prog_delays->m_merged_client_delay) / sample_duration : 0,
							(prog_delays)?((double)prog_delays->m_local_processing_delay_ns) / sample_duration : 0);

						g_logger.format(sinsp_logger::SEV_DEBUG,
							"  time)proc:%.2lf%% file:%.2lf%%(%" PRIu64 "b) net:%.2lf%% other:%.2lf%%",
							procinfo->m_proc_metrics.get_processing_percentage() * 100,
							procinfo->m_proc_metrics.get_file_percentage() * 100,
							(uint64_t)(procinfo->m_proc_metrics.m_tot_io_file.m_bytes_in + procinfo->m_proc_metrics.m_tot_io_file.m_bytes_out),
							procinfo->m_proc_metrics.get_net_percentage() * 100,
							procinfo->m_proc_metrics.get_other_percentage() * 100);
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

				//
				// Update the host metrics with the info coming from this process
				//
				if(procinfo != NULL)
				{
					if(procinfo->m_proc_transaction_metrics.m_counter.m_count_in != 0)
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
		if(it->second.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_CLOSED)
		{
			//
			// Yes, remove the thread from the table, but NOT if the event currently under processing is
			// an exit for this process. In that case we wait until next sample.
			// Note: we clear the metrics no matter what because m_thread_manager->remove_thread might
			//       not actually remove the thread if it has childs.
			//
			it->second.m_ainfo->clear_all_metrics();

			if(evt != NULL && evt->get_type() == PPME_PROCEXIT_E && evt->m_tinfo == &it->second)
			{
				++it;
			}
			else
			{
				m_inspector->m_thread_manager->remove_thread(it++);
			}
		}
		else
		{
			//
			// Clear the thread metrics, so we're ready for the next sample
			//
			it->second.m_ainfo->clear_all_metrics();
			++it;
		}
	}

	m_old_global_total_jiffies = cur_global_total_jiffies;
}

void sinsp_analyzer::emit_aggregated_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
	process_tuple tuple;
	bool aggregate_external_clients = false;
	set<uint32_t> unique_external_ips;

	m_reduced_ipv4_connections.clear();

	//
	// First partial pass to determine if external connections need to be coalesced
	//
	for(cit = m_inspector->m_ipv4_connections->m_connections.begin(); 
		cit != m_inspector->m_ipv4_connections->m_connections.end(); 
		++cit)
	{
		if(cit->second.is_server_only())
		{
			uint32_t sip = cit->first.m_fields.m_sip;

			if(!m_inspector->m_network_interfaces->is_ipv4addr_local(sip))
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
	// Go through the list and perform the aggegation
	//
	for(cit = m_inspector->m_ipv4_connections->m_connections.begin(); 
		cit != m_inspector->m_ipv4_connections->m_connections.end();)
	{
		tuple.m_fields.m_spid = cit->second.m_spid;
		tuple.m_fields.m_dpid = cit->second.m_dpid;
		tuple.m_fields.m_sip = cit->first.m_fields.m_sip;
		tuple.m_fields.m_dip = cit->first.m_fields.m_dip;
		tuple.m_fields.m_sport = 0;
		tuple.m_fields.m_dport = cit->first.m_fields.m_dport;
		tuple.m_fields.m_l4proto = cit->first.m_fields.m_l4proto;

		if(!cit->second.is_client_and_server())
		{
			if(cit->second.is_server_only())
			{
				//
				// If external client aggregation is enabled, this is a server connection, and 
				// the client address is outside the subnet, mask it so it get aggregated
				//
				if(aggregate_external_clients)
				{
					if(!m_inspector->m_network_interfaces->is_ipv4addr_local(cit->first.m_fields.m_sip))
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
		// Look for the entry in the reduced connection table
		//
		sinsp_connection& conn = m_reduced_ipv4_connections[tuple];

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

		//
		// Has this connection been closed druring this sample?
		//
		if(cit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
		{
			//
			// Yes, remove the connection from the table
			//
			m_inspector->m_ipv4_connections->m_connections.erase(cit++);
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
	for(acit = m_reduced_ipv4_connections.begin(); 
		acit != m_reduced_ipv4_connections.end(); ++acit)
	{
		//
		// Skip connection that had no activity during the sample
		//
		if(!acit->second.is_active())
		{
			continue;
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

		conn->set_spid(acit->second.m_spid);
		conn->set_stid(acit->second.m_stid);
		conn->set_dpid(acit->second.m_dpid);
		conn->set_dtid(acit->second.m_dtid);

		acit->second.m_metrics.to_protobuf(conn->mutable_counters());
		acit->second.m_transaction_metrics.to_protobuf(conn->mutable_counters()->mutable_transaction_counters());
		
		//
		// The timestamp field is used to count the number of sub-connections
		//
		conn->mutable_counters()->set_n_aggregated_connections((uint32_t)acit->second.m_timestamp);
	}
}

void sinsp_analyzer::emit_full_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;

	for(cit = m_inspector->m_ipv4_connections->m_connections.begin(); 
		cit != m_inspector->m_ipv4_connections->m_connections.end();)
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
			conn->set_stid(cit->second.m_stid);
			conn->set_dpid(cit->second.m_dpid);
			conn->set_dtid(cit->second.m_dtid);

			cit->second.m_metrics.to_protobuf(conn->mutable_counters());
			cit->second.m_transaction_metrics.to_protobuf(conn->mutable_counters()->mutable_transaction_counters());
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
			m_inspector->m_ipv4_connections->m_connections.erase(cit++);
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

void sinsp_analyzer::flush(sinsp_evt* evt, uint64_t ts, bool is_eof)
{
	uint32_t j;

	m_n_flushes++;

	for(j = 0; ts >= m_next_flush_time_ns; j++)
	{
		uint64_t sample_duration = m_inspector->m_configuration.get_analyzer_sample_length_ns();

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
			//
			// Update the times
			//
			m_prev_flush_time_ns = m_next_flush_time_ns;
			m_next_flush_time_ns += sample_duration;

			ASSERT(m_next_flush_time_ns / sample_duration * sample_duration == m_next_flush_time_ns);
			ASSERT(m_prev_flush_time_ns / sample_duration * sample_duration == m_prev_flush_time_ns);

			//
			// Calculate CPU load
			//
			m_procfs_parser->get_cpus_load(&m_cpu_loads, &m_cpu_idles, &m_cpu_steals);
			m_total_process_cpu = 0; // this will be calculated when scannin the processes

			//
			// Flush the scheduler analyzer
			//
			m_sched_analyzer2->flush(evt, m_prev_flush_time_ns, is_eof);

			if(m_prev_flush_time_ns - m_last_transaction_delays_update_time > TRANSACTION_DELAYS_INTERVAL_NS)
			{
				m_last_transaction_delays_update_time = m_prev_flush_time_ns;
			}

			//
			// Reset the protobuffer
			//
			m_metrics->Clear();

			//
			// Reset the aggreagted host metrics
			//
			m_host_metrics.clear();
			m_host_req_metrics.clear();

			////////////////////////////////////////////////////////////////////////////
			// EMIT PROCESSES
			////////////////////////////////////////////////////////////////////////////
			emit_processes(evt, sample_duration, is_eof);

			////////////////////////////////////////////////////////////////////////////
			// EMIT CONNECTIONS
			////////////////////////////////////////////////////////////////////////////
			g_logger.format(sinsp_logger::SEV_DEBUG, 
				"IPv4 table size:%d",
				m_inspector->m_ipv4_connections->m_connections.size());

			if(m_inspector->m_ipv4_connections->get_n_drops() != 0)
			{
				g_logger.format(sinsp_logger::SEV_ERROR, 
					"IPv4 table drops:%d",
					m_inspector->m_ipv4_connections->get_n_drops());

				m_inspector->m_ipv4_connections->clear_n_drops();
			}

			//
			// Aggregate external connections and limit the number of entries in the connection table
			//
			if(m_inspector->m_configuration.get_aggregate_connections_in_proto())
			{
				emit_aggregated_connections();
			}
			else
			{
				emit_full_connections();
			}

			//
			// Go though the list of unix connections and for the moment just clean it up
			//
			g_logger.format(sinsp_logger::SEV_DEBUG, 
				"unix table size:%d",
				m_inspector->m_unix_connections->m_connections.size());

			if(m_inspector->m_unix_connections->get_n_drops() != 0)
			{
				g_logger.format(sinsp_logger::SEV_ERROR, 
					"IPv4 table size:%d",
					m_inspector->m_unix_connections->m_connections.size());

				m_inspector->m_unix_connections->clear_n_drops();
			}

			unordered_map<unix_tuple, sinsp_connection, unixt_hash, unixt_cmp>::iterator ucit;
			for(ucit = m_inspector->m_unix_connections->m_connections.begin(); 
				ucit != m_inspector->m_unix_connections->m_connections.end();)
			{
				//
				// Has this connection been closed druring this sample?
				//
				if(ucit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					//
					// Yes, remove the connection from the table
					//
					m_inspector->m_unix_connections->m_connections.erase(ucit++);
				}
				else
				{
					++ucit;
				}
			}

			//
			// Go though the list of pipe connections and for the moment just clean it up
			//
			g_logger.format(sinsp_logger::SEV_DEBUG, 
				"pipe table size:%d",
				m_inspector->m_pipe_connections->m_connections.size());

			unordered_map<uint64_t, sinsp_connection, hash<uint64_t>, equal_to<uint64_t>>::iterator pcit;
			for(pcit = m_inspector->m_pipe_connections->m_connections.begin(); 
				pcit != m_inspector->m_pipe_connections->m_connections.end();)
			{
				//
				// Has this connection been closed druring this sample?
				//
				if(pcit->second.m_analysis_flags & sinsp_connection::AF_CLOSED)
				{
					//
					// Yes, remove the connection from the table
					//
					m_inspector->m_pipe_connections->m_connections.erase(pcit++);
				}
				else
				{
					++pcit;
				}
			}

			////////////////////////////////////////////////////////////////////////////
			// EMIT INTERFACES
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
			m_metrics->set_machine_id(m_inspector->m_configuration.get_machine_id());
			m_metrics->set_customer_id(m_inspector->m_configuration.get_customer_id());
			m_metrics->set_timestamp_ns(m_prev_flush_time_ns);

			m_metrics->mutable_hostinfo()->set_hostname(sinsp_gethostname());
			m_metrics->mutable_hostinfo()->set_num_cpus(m_machine_info->num_cpus);
			m_metrics->mutable_hostinfo()->set_physical_memory_size_bytes(m_inspector->m_machine_info->memory_size_bytes);

			ASSERT(m_cpu_loads.size() == 0 || m_cpu_loads.size() == m_machine_info->num_cpus);
			ASSERT(m_cpu_loads.size() == m_cpu_steals.size());
			string cpustr;

			uint32_t totcpuload = 0;
			uint32_t totcpusteal = 0;

			for(j = 0; j < m_cpu_loads.size(); j++)
			{
				cpustr += to_string(m_cpu_loads[j]) + "(" + to_string(m_cpu_steals[j]) + ") ";
				m_metrics->mutable_hostinfo()->add_cpu_loads(m_cpu_loads[j] * 100);
				m_metrics->mutable_hostinfo()->add_cpu_steal(m_cpu_steals[j] * 100);

				totcpuload += m_cpu_loads[j];
				totcpusteal += m_cpu_steals[j];
			}

			ASSERT(totcpuload <= 100 * m_cpu_loads.size());
			ASSERT(totcpusteal <= 100 * m_cpu_loads.size());

			if(totcpuload < m_total_process_cpu)
			{
				totcpuload = m_total_process_cpu;
			}

			if(totcpuload != 0)
			{
				//ASSERT(totcpuload + 10 >= m_total_process_cpu);
				//ASSERT(m_total_process_cpu <= totcpuload + 10);
			}

			if(m_cpu_loads.size() != 0)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "CPU:%s", cpustr.c_str());
			}		

			//
			// Machine info
			//
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_capacity_score((uint32_t)(m_host_metrics.m_capacity_score * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(m_host_metrics.m_stolen_capacity_score * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_connection_queue_usage_pct(m_host_metrics.m_connection_queue_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_usage_pct(m_host_metrics.m_fd_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_resident_memory_usage_kb(m_procfs_parser->get_global_mem_usage_kb());
			m_host_metrics.m_syscall_errors.to_protobuf(m_metrics->mutable_hostinfo()->mutable_syscall_errors());

			//
			// Transactions
			//
			m_delay_calculator->compute_host_delays(m_host_transaction_delays);

			m_host_transaction_counters.to_protobuf(m_metrics->mutable_hostinfo()->mutable_transaction_counters());

			if(m_host_transaction_delays->m_local_processing_delay_ns != -1)
			{
				m_metrics->mutable_hostinfo()->set_transaction_processing_delay(m_host_transaction_delays->m_local_processing_delay_ns);
			}

			//
			// Time splits
			//
			m_host_metrics.m_metrics.to_protobuf(m_metrics->mutable_hostinfo()->mutable_tcounters(), sample_duration);

			m_host_req_metrics.to_reqprotobuf(m_metrics->mutable_hostinfo()->mutable_reqcounters(), sample_duration);

			m_io_net.to_protobuf(m_metrics->mutable_hostinfo()->mutable_external_io_net(), 1);
			m_metrics->mutable_hostinfo()->mutable_external_io_net()->set_time_ns_out(0);

			g_logger.format(sinsp_logger::SEV_DEBUG,
				"host times: proc:%.2lf%% file:%.2lf%%(%" PRIu64 "b) net:%.2lf%% other:%.2lf%%",
				m_host_metrics.m_metrics.get_processing_percentage() * 100,
				m_host_metrics.m_metrics.get_file_percentage() * 100,
				(uint64_t)(m_host_metrics.m_metrics.m_tot_io_file.m_bytes_in + m_host_metrics.m_metrics.m_tot_io_file.m_bytes_out),
				m_host_metrics.m_metrics.get_net_percentage() * 100,
				m_host_metrics.m_metrics.get_other_percentage() * 100);

#ifdef _DEBUG
			double totpct = m_host_metrics.m_metrics.get_processing_percentage() +
				m_host_metrics.m_metrics.get_file_percentage() + 
				m_host_metrics.m_metrics.get_net_percentage() +
				m_host_metrics.m_metrics.get_other_percentage();

			ASSERT(totpct == 0 || (totpct > 0.99 && totpct < 1.01));
#endif // _DEBUG

			if(m_host_transaction_counters.m_counter.m_count_in + m_host_transaction_counters.m_counter.m_count_out != 0)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
					" host h:%.2f(s:%.2f)",
					m_host_metrics.m_capacity_score,
					m_host_metrics.m_stolen_capacity_score);

				g_logger.format(sinsp_logger::SEV_DEBUG,
					"  trans)in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf gin:%lf gout:%lf gloc:%lf",
					m_host_transaction_counters.m_counter.m_count_in,
					m_host_transaction_counters.m_counter.m_count_out,
					(float)m_host_transaction_counters.m_counter.m_time_ns_in / 1000000000,
					(float)m_client_tr_time_by_servers / 1000000000,
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

			////////////////////////////////////////////////////////////////////////////
			// Serialize the whole crap
			////////////////////////////////////////////////////////////////////////////
			serialize(m_prev_flush_time_ns);
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// END OF SAMPLE CLEANUPS
	///////////////////////////////////////////////////////////////////////////

	//
	// Clear the transaction state
	//
	g_logger.format(sinsp_logger::SEV_DEBUG, 
		"# Client Transactions:%d",
		m_inspector->get_transactions()->m_n_client_transactions);
	g_logger.format(sinsp_logger::SEV_DEBUG, 
		"# Server Transactions:%d",
		m_inspector->get_transactions()->m_n_server_transactions);

	m_inspector->get_transactions()->m_n_client_transactions = 0;
	m_inspector->get_transactions()->m_n_server_transactions = 0;

	m_host_transaction_counters.clear();
	m_client_tr_time_by_servers = 0;

	for(j = 0; j < m_machine_info->num_cpus; j++)
	{
		m_host_server_transactions[j].clear();
		m_host_client_transactions[j].clear();
	}

	//
	// Clear the network I/O counter
	//
	m_io_net.clear();

	//
	// Run the periodic connection and thread table cleanup
	//
	m_inspector->remove_expired_connections(ts);
	m_inspector->m_thread_manager->remove_inactive_threads();

	if(evt)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "----- %" PRIu64 "", evt->get_num() - m_prev_sample_evtnum);
		m_prev_sample_evtnum = evt->get_num();
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

void sinsp_analyzer::parse_accept_exit(sinsp_evt* evt)
{
	//
	// Extract the request queue length 
	//
	sinsp_evt_param *parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint8_t));
	uint8_t queueratio = *(uint8_t*)parinfo->m_val;
	ASSERT(queueratio <= 100);

	if(queueratio > evt->m_tinfo->m_ainfo->m_connection_queue_usage_pct)
	{
		evt->m_tinfo->m_ainfo->m_connection_queue_usage_pct = queueratio;
	}

	//
	// If this comes after a wait, reset the last wait time, since we don't count 
	// time waiting for an accept as I/O time
	//
	evt->m_tinfo->m_ainfo->m_last_wait_duration_ns = 0;
}

void sinsp_analyzer::parse_select_poll_epollwait_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	uint16_t etype = evt->get_type();

	if(etype != evt->m_tinfo->m_lastevent_type + 1)
	{
		//
		// Packet drop. Previuos event didn't have a chance to 
		//
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;

		if(tinfo == NULL)
		{
			ASSERT(false);
			return;
		}

		if(tinfo->is_lastevent_data_valid())
		{
			//
			// We categorize this based on the next I/O operation only if the number of 
			// FDs that were waited for is 1
			//
			if(retval == 0)
			{
				tinfo->m_ainfo->m_last_wait_duration_ns = 0;
			}
			else
			{
				//
				// If this was a wait on a *single* fd, we can easily categorize it with certainty and
				// we encode the delta as a positive number.
				// If this was a wait on multiple FDs, we encode the delta as a negative number so
				// the next steps will know that it needs to be handled with more care.
				//
				uint64_t sample_duration = m_inspector->m_configuration.get_analyzer_sample_length_ns();
				uint64_t ts = evt->get_ts();

				tinfo->m_ainfo->m_last_wait_end_time_ns = ts;
				uint64_t start_time_ns = MAX(ts - ts % sample_duration, *(uint64_t*)evt->m_tinfo->m_lastevent_data);

				if(retval == 1)
				{
					tinfo->m_ainfo->m_last_wait_duration_ns = ts - start_time_ns;
				}
				else
				{
					tinfo->m_ainfo->m_last_wait_duration_ns = start_time_ns - ts;
				}
			}
		}
	}
}

void sinsp_analyzer::process_event(sinsp_evt* evt)
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
		if(etype == PPME_SCHEDSWITCH_E)
		{
			m_sched_analyzer2->process_event(evt);
			return;
		}
		else if(etype == PPME_SOCKET_ACCEPT_X || etype == PPME_SOCKET_ACCEPT4_X)
		{
			parse_accept_exit(evt);
		}
		else if(etype == PPME_SYSCALL_SELECT_X || etype == PPME_SYSCALL_POLL_X || 
			etype == PPME_SYSCALL_EPOLLWAIT_X)
		{
			parse_select_poll_epollwait_exit(evt);
		}
	}
	else
	{
		ts = m_next_flush_time_ns;
		flush(evt, ts, true);
		return;
	}

	//
	// Check if it's time to flush
	//
	if(ts >= m_next_flush_time_ns)
	{
		flush(evt, ts, false);
	}

	//
	// This is where normal event parsing starts.
	// The following code is executed for every event
	//
	if(evt->m_tinfo == NULL)
	{
		//
		// No thread associated to this event, nothing to do
		//
		return;
	}

	tainfo = evt->m_tinfo->m_ainfo;

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
			
			m_host_metrics.m_syscall_errors.m_table[evt->m_errorcode].m_count++;
			
#ifdef ANALYZER_EMITS_PROGRAMS
			sinsp_threadinfo* parentinfo = evt->m_tinfo->get_main_program_thread();
#else
			sinsp_threadinfo* parentinfo = evt->m_tinfo->get_main_thread();
#endif
			if(parentinfo != NULL)
			{
				parentinfo->m_ainfo->allocate_procinfo_if_not_present();
				parentinfo->m_ainfo->m_procinfo->m_syscall_errors.m_table[evt->m_errorcode].m_count++;
			}
			else
			{
				ASSERT(false);
			}
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
