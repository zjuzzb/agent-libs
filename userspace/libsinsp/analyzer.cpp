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
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"

#define DUMP_TO_DISK

#undef ANALYZER_EMITS_PROGRAMS

sinsp_analyzer::sinsp_analyzer(sinsp* inspector) :
	m_aggregated_ipv4_table(inspector)
{
	m_inspector = inspector;
	m_next_flush_time_ns = 0;
	m_prev_flush_time_ns = 0;
	m_metrics = new draiosproto::metrics;
	m_serialization_buffer = (char*)malloc(MIN_SERIALIZATION_BUF_SIZE_BYTES);
	if(!m_serialization_buffer)
	{
		char tbuf[256];
		snprintf(tbuf, sizeof(tbuf), "memory allocation error at %s:%d", 
			__FILE__, __LINE__);
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

	m_procfs_parser = new sinsp_procfs_parser(m_machine_info->num_cpus, m_machine_info->memory_size_bytes / 1024);
	m_procfs_parser->get_global_cpu_load(&m_old_global_total_jiffies);

	m_sched_analyzer = new sinsp_sched_analyzer(inspector, m_machine_info->num_cpus);

	m_score_calculator = new sinsp_scores(inspector, m_sched_analyzer);

	m_server_transactions_per_cpu = vector<vector<pair<uint64_t, uint64_t>>>(m_machine_info->num_cpus);
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

	if(m_sched_analyzer)
	{
		delete m_sched_analyzer;
	}
}

void sinsp_analyzer::on_capture_start()
{
	ASSERT(m_sched_analyzer != NULL);
	m_sched_analyzer->on_capture_start();
}

void sinsp_analyzer::set_sample_callback(analyzer_callback_interface* cb)
{
	ASSERT(cb != NULL);
	ASSERT(m_sample_callback == NULL);
	m_sample_callback = cb;
}

bool sinsp_analyzer::is_main_program_thread(sinsp_threadinfo* ptinfo)
{
	if(ptinfo->m_progid != -1)
	{
		return false;
	}
	else
	{
		return ptinfo->m_tid == ptinfo->m_pid;
	}
}

sinsp_threadinfo* sinsp_analyzer::get_main_program_thread(sinsp_threadinfo* ptinfo)
{
	if(ptinfo->m_main_program_thread == NULL)
	{
		//
		// Is this a sub-process?
		//
		if(ptinfo->m_progid != -1)
		{
			//
			// Yes, this is a child sub-process. Find the progrm root thread.
			//
			sinsp_threadinfo *ttinfo = m_inspector->get_thread(ptinfo->m_progid, true);
			if(NULL == ttinfo)
			{
				ASSERT(false);
				return NULL;
			}

			sinsp_threadinfo *pptinfo = get_main_program_thread(ttinfo);

			ptinfo->m_main_program_thread = pptinfo;
		}
		else
		{
			//
			// Is this a child thread?
			//
			if(ptinfo->m_pid == ptinfo->m_tid)
			{
				//
				// No, this is either a single thread process or the root thread of a
				// multithread process,
				//
				return ptinfo;
			}
			else
			{
				//
				// Yes, this is a child thread. Find the process root thread.
				//
				sinsp_threadinfo *ttinfo = m_inspector->get_thread(ptinfo->m_pid, true);
				if(NULL == ttinfo)
				{
					ASSERT(false);
					return NULL;
				}

				ptinfo->m_main_program_thread = ttinfo;
			}
		}
	}

	return ptinfo->m_main_program_thread;
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
	uint32_t full_len = tlen + sizeof(uint32_t);

	//
	// If the buffer is to small, eapnd it
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
			char *estr = g_logger.format(sinsp_logger::SEV_CRITICAL, "memory allocation error at %s:%d", 
				__FILE__, __LINE__);
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
		ArrayOutputStream* array_output = new ArrayOutputStream(m_serialization_buffer + sizeof(uint32_t), tlen);
		GzipOutputStream* gzip_output = new GzipOutputStream(array_output);

		m_metrics->SerializeToZeroCopyStream(gzip_output);
		gzip_output->Close();

		uint32_t compressed_size = (uint32_t)array_output->ByteCount();

		*(uint32_t*) m_serialization_buffer = compressed_size;
		*len = *(uint32_t*) m_serialization_buffer;
		delete array_output;
		return m_serialization_buffer + sizeof(uint32_t);
#endif
	}
	else
	{
		ArrayOutputStream* array_output = new ArrayOutputStream(m_serialization_buffer + sizeof(uint32_t), tlen);
		m_metrics->SerializeToZeroCopyStream(array_output);

		*(uint32_t*) m_serialization_buffer = tlen;
		*len = *(uint32_t*) m_serialization_buffer;
		delete array_output;
		return m_serialization_buffer + sizeof(uint32_t);
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
		m_sample_callback->sinsp_analyzer_data_ready(ts, buf - sizeof(uint32_t));
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

//
// Based on the transaction counters for this process, calculate the delay in trasanction 
// handling that the process introduces
//
uint64_t sinsp_analyzer::compute_thread_transaction_delay(sinsp_transaction_counters* trcounters)
{
	if(trcounters->m_counter.m_count_in == 0)
	{
		//
		// This is not a server
		//
		return 0;
	}
	else
	{
		ASSERT(trcounters->m_counter.m_time_ns_in != 0);

		int64_t res = trcounters->m_counter.m_time_ns_in - trcounters->m_counter.m_time_ns_out;

		if(res <= 0)
		{
			return 0;
		}
		else
		{
			return res;
		}
	}
}

void sinsp_analyzer::compute_host_transaction_delay()
{
	if(m_host_transaction_metrics.m_counter.m_count_in == 0)
	{
		//
		// This host is not serving transactions
		//
		m_host_transaction_delay_ns = -1;
	}
	else
	{
		ASSERT(m_host_transaction_metrics.m_counter.m_time_ns_in != 0);

		if(m_client_tr_time_by_servers == 0)
		{
			//
			// No outbound connections made by servers: it means that This node is a
			// leaf in the connection tree and the host_transaction_delay euqals to the
			// input transaction processing time.
			//
			m_host_transaction_delay_ns = m_host_transaction_metrics.m_counter.m_time_ns_in;
			return;
		}

		int64_t res = m_host_transaction_metrics.m_counter.m_time_ns_in - m_client_tr_time_by_servers;

		if(res <= 0)
		{
			m_host_transaction_delay_ns = 0;
		}
		else
		{
			m_host_transaction_delay_ns = res;
		}
	}
}

void sinsp_analyzer::emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof)
{
	uint64_t delta;
	sinsp_evt::category* cat;
	sinsp_evt::category tcat;
	uint32_t n_server_threads = 0;

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
	// First pass of the list of threads: emit the metrics (if defined)
	// and aggregate them into processes
	//
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

			add_syscall_time(&it->second.m_metrics, 
				cat, 
				delta,
				0,
				false);

			//
			// Flag the thread so we know that part of this event has already been attributed
			//
			it->second.m_th_analysis_flags |= sinsp_threadinfo::AF_PARTIAL_METRIC;
		}

		//
		// Some assertions to validate that everything looks like expected
		//
#ifdef _DEBUG
		sinsp_counter_time ttot;
		it->second.m_metrics.get_total(&ttot);
		ASSERT(is_eof || ttot.m_time_ns % sample_duration == 0);
#endif
		//
		// Go through the FD list to flush the transactions that haven't been active for a while
		//
		it->second.flush_inactive_transactions(m_prev_flush_time_ns, sample_duration);

		//
		// Add this thread's counters to the process ones...
		//
#ifdef ANALYZER_EMITS_PROGRAMS
		sinsp_threadinfo* mtinfo = get_main_program_thread(&it->second);
#else
		sinsp_threadinfo* mtinfo = it->second.get_main_thread();
#endif
		it->second.m_transaction_processing_delay_ns = compute_thread_transaction_delay(&it->second.m_transaction_metrics);
		mtinfo->add_all_metrics(&it->second);

		//
		// ... And to the host ones
		//
		m_host_transaction_metrics.add(&it->second.m_external_transaction_metrics);

		if(it->second.m_transaction_metrics.m_counter.m_count_in != 0)
		{
			n_server_threads++;
			m_client_tr_time_by_servers += it->second.m_external_transaction_metrics.m_counter.m_time_ns_out;
		}

		//
		// Dump the thread info into the protobuf
		//
#ifdef ANALYZER_EMITS_THREADS
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

	//
	// Between the first and the second pass of the thread list, calculate the 
	// host transaction delay, the local versus next tier processing time ratio and 
	// the health score for the machine.
	//
	compute_host_transaction_delay();

	// 1 means no next tiers delay
	m_local_remote_ratio = 1;
	if(m_inspector->m_analyzer->m_host_transaction_delay_ns != -1)
	{
		if(m_inspector->m_analyzer->m_host_transaction_metrics.m_counter.m_time_ns_in != 0)
		{
			m_local_remote_ratio = (float)m_inspector->m_analyzer->m_host_transaction_delay_ns / 
				(float)m_inspector->m_analyzer->m_host_transaction_metrics.m_counter.m_time_ns_in;
		}
	}

	if(m_transactions_with_cpu.size() != 0)
	{
		int32_t syshscore_g;

/*
		syshscore = (float)m_score_calculator->get_system_capacity_score_bycpu_old(&m_transactions_with_cpu,
			n_server_threads,
			m_prev_flush_time_ns, sample_duration);

		g_logger.format(sinsp_logger::SEV_DEBUG,
			"1!!%f",
			syshscore);

		syshscore = (float)m_score_calculator->get_system_capacity_score_bycpu(&m_server_transactions_per_cpu,
			n_server_threads,
			m_prev_flush_time_ns, sample_duration);

		g_logger.format(sinsp_logger::SEV_DEBUG,
			"2!!%f",
			syshscore);
*/
		m_host_metrics.m_capacity_score = m_score_calculator->get_system_capacity_score_bycpu_3(&m_server_transactions_per_cpu,
			n_server_threads,
			m_prev_flush_time_ns, sample_duration);

		g_logger.format(sinsp_logger::SEV_DEBUG,
			"3!!%.2f",
			m_host_metrics.m_capacity_score);

		syshscore_g = m_score_calculator->get_system_capacity_score_global(&m_transactions_with_cpu,
			n_server_threads,
			m_prev_flush_time_ns, sample_duration);

		g_logger.format(sinsp_logger::SEV_DEBUG,
			"2!!%" PRId32,
			syshscore_g);

		if(m_host_metrics.m_capacity_score == -1)
		{
			m_host_metrics.m_capacity_score = (float)syshscore_g;
		}

		m_transactions_with_cpu.clear();
		for(uint32_t k = 0; k < m_server_transactions_per_cpu.size(); k++)
		{
			m_server_transactions_per_cpu[k].clear();
		}
	}

	//
	// Second pass of the list of threads: aggreagate processes into programs.
	// NOTE: this pass can be integrated in the previous one. We keep it seperate for.
	// the moment so we have the option to emit single processes. This is useful until
	// we clearly decide what to put in the UI.
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

	for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
		it != m_inspector->m_thread_manager->m_threadtable.end(); 
		)
	{
		//
		// If this is the main thread of a process, add an entry into the processes
		// section too
		//
#ifdef ANALYZER_EMITS_PROGRAMS
		if(is_main_program_thread(&it->second))
#else
		if(it->second.is_main_thread())
#endif
		{
			int32_t cpuload = -1;
			int64_t memsize;
			int64_t pid = it->second.m_pid;

#ifdef ANALYZER_EMITS_PROCESSES
			sinsp_counter_time tot;
	
			ASSERT(it->second.m_procinfo);
			it->second.m_procinfo->m_proc_metrics.get_total(&tot);
			ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);

			if(m_inspector->m_islive)
			{
				cpuload = m_procfs_parser->get_process_cpu_load_and_mem(pid, 
					&it->second.m_old_proc_jiffies, 
					cur_global_total_jiffies - m_old_global_total_jiffies,
					&memsize);
			}

			if(tot.m_count != 0 || cpuload != 0)
			{
				//
				// Basic values
				//
				draiosproto::process* proc = m_metrics->add_processes();
				proc->set_pid(pid);
				proc->set_comm(it->second.m_comm);
				proc->set_exe(it->second.m_exe);
				for(vector<string>::const_iterator arg_it = it->second.m_args.begin(); 
					arg_it != it->second.m_args.end(); ++arg_it)
				{
					proc->add_args(*arg_it);
				}

				if(cpuload != -1)
				{
					proc->mutable_resource_counters()->set_cpu_pct(cpuload);
					proc->mutable_resource_counters()->set_resident_memory_usage_kb(memsize);
				}
				else
				{
					proc->mutable_resource_counters()->set_cpu_pct(0);
					proc->mutable_resource_counters()->set_resident_memory_usage_kb(0);
				}

				if(tot.m_count != 0)
				{
					//
					// Transaction-related metrics
					//
					it->second.m_procinfo->m_proc_metrics.to_protobuf(proc->mutable_tcounters());
					it->second.m_procinfo->m_proc_transaction_metrics.to_protobuf(proc->mutable_transaction_counters());
					proc->set_transaction_processing_delay(it->second.m_procinfo->m_proc_transaction_processing_delay_ns);

					//
					// Health-related metrics
					//
					it->second.m_procinfo->m_capacity_score = m_score_calculator->get_process_capacity_score(m_host_metrics.m_capacity_score, &it->second);
					proc->mutable_resource_counters()->set_capacity_score((uint32_t)(it->second.m_procinfo->m_capacity_score * 100));
					proc->mutable_resource_counters()->set_connection_queue_usage_pct(it->second.m_procinfo->m_connection_queue_usage_pct);
					proc->mutable_resource_counters()->set_fd_usage_pct(it->second.m_procinfo->m_fd_usage_pct);

					//
					// Error-related metrics
					//
					it->second.m_procinfo->m_syscall_errors.to_protobuf(proc->mutable_syscall_errors());

#if 1
					if(it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_count_in != 0)
					{
						uint64_t trtimein = it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_in;
						uint64_t trtimeout = it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_out;
						uint32_t trcountin = it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_count_in;
						uint32_t trcountout = it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_count_out;

						g_logger.format(sinsp_logger::SEV_DEBUG,
							" %s (%" PRIu64 ")%" PRIu64 " h:%.2f cpu:%" PRId32 " in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf tloc:%lf %%f:%" PRIu32 " %%c:%" PRIu32,
							it->second.m_comm.c_str(),
	//						(it->second.m_args.size() != 0)? it->second.m_args[0].c_str() : "",
							it->second.m_tid,
							it->second.m_nchilds + 1,
							it->second.m_procinfo->m_capacity_score,
							cpuload,
							it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_count_in,
							it->second.m_procinfo->m_proc_transaction_metrics.m_counter.m_count_out,
							//trcountin? ((double)trtimein) / trcountin / 1000000000 : 0,
							//trcountout? ((double)trtimeout) / trcountin / 1000000000 : 0,
							//trcountin? ((double)it->second.m_procinfo->m_proc_transaction_processing_delay_ns) / trcountin / 1000000000 : 0,
							trcountin? ((double)trtimein) / 1000000000 : 0,
							trcountout? ((double)trtimeout) / 1000000000 : 0,
							trcountin? ((double)it->second.m_procinfo->m_proc_transaction_processing_delay_ns) / 1000000000 : 0,
							it->second.m_fd_usage_pct,
							it->second.m_connection_queue_usage_pct);
					}
#endif
				}
#endif // ANALYZER_EMITS_PROCESSES

				//
				// Update the host metrics with the info coming from this process
				//
				if(it->second.m_procinfo != NULL)
				{
					m_host_metrics.add(it->second.m_procinfo);
				}
				else
				{
					ASSERT(false);
				}
			}
		}
/*
		if(it->second.m_transaction_metrics.m_incoming.m_count != 0)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
				"*\t%s %s (%" PRIu64 ") (%" PRIu64 ") in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf tloc:%lf %%fd:%" PRIu32 " %%conns:%" PRIu32 " rest:%" PRIu64,
				it->second.m_comm.c_str(),
				(it->second.m_args.size() != 0)? it->second.m_args[0].c_str() : "",
				it->second.m_tid,
				it->second.m_nchilds + 1,
				it->second.m_transaction_metrics.m_incoming.m_count,
				it->second.m_transaction_metrics.m_outgoing.m_count,
				((double)it->second.m_transaction_metrics.m_incoming.m_time_ns) / 1000000000,
				((double)it->second.m_transaction_metrics.m_outgoing.m_time_ns) / 1000000000,
				((double)it->second.m_transaction_processing_delay_ns) / 1000000000,
				it->second.m_fd_usage_pct,
				it->second.m_connection_queue_usage_pct,
				it->second.m_rest_time_ns);
		}
*/

		//
		// Has this thread been closed druring this sample?
		//
		if(it->second.m_th_analysis_flags & sinsp_threadinfo::AF_CLOSED)
		{
			//
			// Yes, remove the thread from the table, but NOT if the event currently under processing is
			// an exit for this process. In that case we wait until next sample.
			//
			if(evt != NULL && evt->get_type() == PPME_PROCEXIT_E && evt->m_tinfo == &it->second)
			{
				it->second.clear_all_metrics();
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
			it->second.clear_all_metrics();
			++it;
		}
	}

	m_old_global_total_jiffies = cur_global_total_jiffies;
}

void sinsp_analyzer::emit_aggregated_connections()
{
	unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
	process_tuple tuple;

	m_reduced_ipv4_connections.clear();
	m_aggregated_ipv4_table.clear();

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

		//
		// If this is a server connection and the client address is outside the subnet, aggregate it
		//
		if(cit->second.is_server_only())
		{
			if(!m_inspector->m_network_interfaces->is_ipv4addr_local(cit->first.m_fields.m_sip))
			{
				tuple.m_fields.m_sip = 0;
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
			conn.m_timestamp = 0;
		}

		//
		// Add this connection's metrics to the aggregated connection's ones
		//
		conn.m_metrics.add(&cit->second.m_metrics);
		conn.m_transaction_metrics.add(&cit->second.m_transaction_metrics);
		conn.m_timestamp++;

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
			// Flush the scheduler analyzer
			//
			m_sched_analyzer->flush(evt, m_prev_flush_time_ns, is_eof);

			//
			// Reset the protobuffer
			//
			m_metrics->Clear();

			//
			// Reset the aggreagted host metrics
			//
			m_host_metrics.clear();

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
			// emit host metrics
			////////////////////////////////////////////////////////////////////////////
			m_metrics->set_machine_id(m_inspector->m_configuration.get_machine_id());
			m_metrics->set_customer_id(m_inspector->m_configuration.get_customer_id());
			m_metrics->set_timestamp_ns(m_prev_flush_time_ns);

			m_metrics->mutable_hostinfo()->set_hostname(sinsp_gethostname());
			m_metrics->mutable_hostinfo()->set_num_cpus(m_machine_info->num_cpus);
			m_metrics->mutable_hostinfo()->set_physical_memory_size_bytes(m_inspector->m_machine_info->memory_size_bytes);

			m_procfs_parser->get_cpus_load(&m_cpu_loads);
			ASSERT(m_cpu_loads.size() == 0 || m_cpu_loads.size() == m_machine_info->num_cpus);
			string cpustr;
			for(j = 0; j < m_cpu_loads.size(); j++)
			{
				cpustr += to_string(m_cpu_loads[j]) + " ";
				m_metrics->mutable_hostinfo()->add_cpu_loads(m_cpu_loads[j]);
			}
			if(m_cpu_loads.size() != 0)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "CPU:%s", cpustr.c_str());
			}		

			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_capacity_score((uint32_t)(m_host_metrics.m_capacity_score * 100));
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_connection_queue_usage_pct(m_host_metrics.m_connection_queue_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_fd_usage_pct(m_host_metrics.m_fd_usage_pct);
			m_metrics->mutable_hostinfo()->mutable_resource_counters()->set_resident_memory_usage_kb(m_procfs_parser->get_global_mem_usage_kb());
			m_host_metrics.m_syscall_errors.to_protobuf(m_metrics->mutable_hostinfo()->mutable_syscall_errors());

			m_host_transaction_metrics.to_protobuf(m_metrics->mutable_hostinfo()->mutable_transaction_counters());

			if(m_host_transaction_delay_ns != -1)
			{
				m_metrics->mutable_hostinfo()->set_transaction_processing_delay(m_host_transaction_delay_ns);
			}

			if(m_host_transaction_metrics.m_counter.m_count_in + m_host_transaction_metrics.m_counter.m_count_out != 0)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, 
					"host tr: in:%" PRIu32 " out:%" PRIu32 " tin:%f tout:%f tloc:%f",
					m_host_transaction_metrics.m_counter.m_count_in,
					m_host_transaction_metrics.m_counter.m_count_out,
					(float)m_host_transaction_metrics.m_counter.m_time_ns_in / 1000000000,
					(float)m_client_tr_time_by_servers / 1000000000,
					(float)m_host_transaction_delay_ns / 1000000000
					);
			}

			////////////////////////////////////////////////////////////////////////////
			// Serialize the whole crap
			////////////////////////////////////////////////////////////////////////////
			serialize(m_prev_flush_time_ns);
		}
	}

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

	m_host_transaction_metrics.clear();
	m_client_tr_time_by_servers = 0;

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

void sinsp_analyzer::process_event(sinsp_evt* evt)
{
	uint64_t ts;
	uint64_t delta;
	sinsp_evt::category cat;
	uint16_t etype;

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
			m_sched_analyzer->process_event(evt);
			return;
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

	//
	// Get the event category and type
	//
	evt->get_category(&cat);

	//
	// Check if this is an event that goes across sample boundaries
	//
	if((evt->m_tinfo->m_th_analysis_flags & sinsp_threadinfo::AF_PARTIAL_METRIC) != 0)
	{
		//
		// Part of this event has already been attributed to the previous sample, 
		// we just include the remaining part
		//
		evt->m_tinfo->m_th_analysis_flags &= ~(sinsp_threadinfo::AF_PARTIAL_METRIC);

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
	}

	//
	// Increase the counter
	//
	bool do_inc_counter = (cat.m_category != EC_PROCESSING);

	add_syscall_time(&evt->m_tinfo->m_metrics, 
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
			sinsp_threadinfo* parentinfo = get_main_program_thread(evt->m_tinfo);
#else
			sinsp_threadinfo* parentinfo = evt->m_tinfo->get_main_thread();
#endif
			if(parentinfo != NULL)
			{
				parentinfo->allocate_procinfo_if_not_present();
				parentinfo->m_procinfo->m_syscall_errors.m_table[evt->m_errorcode].m_count++;
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
			metrics->m_wait.add(cnt_delta, delta);
			break;
		case EC_SCHEDULER:
			break;
		default:
			ASSERT(false);
	}
}
