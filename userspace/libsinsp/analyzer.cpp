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

#define DUMP_TO_DISK

//#undef ANALYZER_SAMPLE_DURATION_NS
//#define ANALYZER_SAMPLE_DURATION_NS 5000000000

sinsp_analyzer::sinsp_analyzer(sinsp* inspector)
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
}

void sinsp_analyzer::set_sample_callback(analyzer_callback_interface* cb)
{
	ASSERT(cb != NULL);
	ASSERT(m_sample_callback == NULL);
	m_sample_callback = cb;
}

char* sinsp_analyzer::serialize_to_bytebuf(OUT uint32_t *len)
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
	ArrayOutputStream* array_output = new ArrayOutputStream(m_serialization_buffer + sizeof(uint32_t), tlen);
   	m_metrics->SerializeToZeroCopyStream(array_output);

	*(uint32_t*) m_serialization_buffer = tlen;
	*len = *(uint32_t*) m_serialization_buffer;
	return m_serialization_buffer + sizeof(uint32_t);
}

void sinsp_analyzer::serialize(uint64_t ts)
{
	char fname[128];
	uint32_t buflen;

	//
	// Serialize to a memory buffer
	//
	char* buf = sinsp_analyzer::serialize_to_bytebuf(&buflen);
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
			ASSERT(false);
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
uint64_t sinsp_analyzer::compute_process_transaction_delay(sinsp_transaction_counters* trcounters)
{
	if(trcounters->m_incoming.m_count == 0)
	{
		//
		// This is a client
		//
		return 0;
	}
	else
	{
		ASSERT(trcounters->m_incoming.m_time_ns != 0);

		int64_t res = trcounters->m_incoming.m_time_ns - trcounters->m_outgoing.m_time_ns;

		if(res <= 0)
		{
			ASSERT(false);
			return 0;
		}
		else
		{
			return res;
		}
	}
}

void sinsp_analyzer::flush(sinsp_evt* evt, uint64_t ts, bool is_eof)
{
	uint32_t j;
	uint64_t delta;
	sinsp_evt::category* cat;
	sinsp_evt::category tcat;

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
			// Reset the protobuffer
			//
			m_metrics->Clear();
			m_metrics->set_machine_id(m_inspector->m_configuration.get_machine_id());
			m_metrics->set_customer_id(m_inspector->m_configuration.get_customer_id());
			m_metrics->set_timestamp_ns(m_prev_flush_time_ns);
			m_metrics->set_hostname(sinsp_gethostname());

			////////////////////////////////////////////////////////////////////////////
			// EMIT PROCESSES
			////////////////////////////////////////////////////////////////////////////
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

						//
						// If this is a wait, IPC or sleep event, attribute it to the rest time.
						// This is a simplification, but should be pretty benign and greatly simplifies
						// the rest time logic.
						//
						if(cat->m_category == EC_WAIT || cat->m_category == EC_IPC ||
							cat->m_category == EC_SLEEP)
						{
							it->second.m_rest_time_ns += delta;
						}
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
					it->second.m_analysis_flags |= sinsp_threadinfo::AF_PARTIAL_METRIC;
				}

				//
				// Some assertions to validate that everything looks like expected
				//
#ifdef _DEBUG
				sinsp_counter_time ttot;
				it->second.m_metrics.get_total(&ttot);
				ASSERT(is_eof || ttot.m_time_ns % sample_duration == 0);

				if(ttot.m_count > 0 && it->second.m_transaction_metrics.m_incoming.m_count != 0)
				{
//					ASSERT(it->second.m_rest_time_ns > 0);
				}

				ASSERT(it->second.m_rest_time_ns <= sample_duration);
#endif
				//
				// Add this thread's counters to the process ones
				//
				sinsp_threadinfo* mtinfo = it->second.get_main_thread();
				it->second.m_transaction_processing_delay_ns = compute_process_transaction_delay(&it->second.m_transaction_metrics);
				mtinfo->add_all_metrics(&it->second);
				
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
			// Second pass of the list of threads: aggreagate processes into programs.
			// NOTE: this pass can be integrated in the previous one. We keep it seperate for.
			// the moment so we have the option to emit single processes. This is useful until
			// we clearly decide what to put in the UI.
			//
#ifdef ANALYZER_EMITS_PROGRAMS
			m_program_table.clear();
#endif

			for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
				it != m_inspector->m_thread_manager->m_threadtable.end(); 
#ifdef ANALYZER_EMITS_PROGRAMS
				++it
#endif
				)
			{
				//
				// If this is the main thread of a process, add an entry into the processes
				// section too
				//
				if(it->second.is_main_thread())
				{
#ifdef ANALYZER_EMITS_PROGRAMS

					//
					// Do the aggregation into programs
					//
					std::pair<unordered_map<string, sinsp_threadinfo*>::iterator, bool> &element = 
						m_program_table.insert(unordered_map<string, sinsp_threadinfo*>::value_type(it->second.m_exe, &it->second));
					if(element.second == false)
					{
						ASSERT(element.first->second != &it->second);
						element.first->second->add_proc_metrics(&it->second);
					}
#endif

					//
					// If defined, emit the processes
					//
#ifdef ANALYZER_EMITS_PROCESSES
					sinsp_counter_time tot;
	
					ASSERT(it->second.m_procinfo);
					it->second.m_procinfo->m_proc_metrics.get_total(&tot);
					ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);

					if(tot.m_count != 0)
					{
						draiosproto::process* proc = m_metrics->add_processes();
						proc->set_pid(it->second.m_pid);
						proc->set_comm(it->second.m_comm);
						proc->set_exe(it->second.m_exe);
						for(vector<string>::const_iterator arg_it = it->second.m_args.begin(); 
							arg_it != it->second.m_args.end(); ++arg_it)
						{
							proc->add_args(*arg_it);
						}

						it->second.m_procinfo->m_proc_metrics.to_protobuf(proc->mutable_tcounters());
						it->second.m_procinfo->m_proc_transaction_metrics.to_protobuf(proc->mutable_transaction_counters());
						proc->set_local_transaction_delay(it->second.m_procinfo->m_proc_transaction_processing_delay_ns);

						proc->set_health_score(it->second.get_process_health_score());
						proc->set_connection_queue_usage_pct(it->second.m_procinfo->m_connection_queue_usage_ratio);
						proc->set_fd_usage_pct(it->second.m_procinfo->m_fd_usage_ratio);

#if 1
						if(it->second.m_procinfo->m_n_rest_time_entries != 0)
						{
							ASSERT(it->second.m_procinfo->m_min_rest_time_ns != 0xFFFFFFFFFFFFFFFF);
							ASSERT(it->second.m_procinfo->m_min_rest_time_ns != 0);
							ASSERT(it->second.m_procinfo->m_max_rest_time_ns != 0);
						}

						if(it->second.m_procinfo->m_proc_transaction_metrics.m_incoming.m_count +
							it->second.m_procinfo->m_proc_transaction_metrics.m_outgoing.m_count != 0)
						{
							g_logger.format(sinsp_logger::SEV_DEBUG,
								"\t%s %s (%" PRIu64 ") (%" PRIu64 ") health:% " PRIu32 " in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf tloc:%lf %%fd:%" PRIu32 " %%conns:%" PRIu32 " %%rest:%" PRIu64 "-%" PRIu64 "-%" PRIu64 "(%" PRIu32 ")",
								it->second.m_comm.c_str(),
								(it->second.m_args.size() != 0)? it->second.m_args[0].c_str() : "",
								it->second.m_tid,
								it->second.m_refcount + 1,
								it->second.get_process_health_score(),
								it->second.m_procinfo->m_proc_transaction_metrics.m_incoming.m_count,
								it->second.m_procinfo->m_proc_transaction_metrics.m_outgoing.m_count,
								((double)it->second.m_procinfo->m_proc_transaction_metrics.m_incoming.m_time_ns) / 1000000000,
								((double)it->second.m_procinfo->m_proc_transaction_metrics.m_outgoing.m_time_ns) / 1000000000,
								((double)it->second.m_procinfo->m_proc_transaction_processing_delay_ns) / 1000000000,
								it->second.m_fd_usage_ratio,
								it->second.m_connection_queue_usage_ratio,
								(it->second.m_procinfo->m_tot_rest_time_ns / it->second.m_procinfo->m_n_rest_time_entries) * 100 / sample_duration,
								it->second.m_procinfo->m_min_rest_time_ns * 100 / sample_duration,
								it->second.m_procinfo->m_max_rest_time_ns * 100 / sample_duration,
								it->second.m_procinfo->m_n_rest_time_entries);
						}
#endif // _DEBUG
					}
#endif // ANALYZER_EMITS_PROCESSES
				}

				//if(it->second.m_transaction_metrics.m_incoming.m_count +
				//	it->second.m_transaction_metrics.m_outgoing.m_count != 0)
				//{
				//	g_logger.format(sinsp_logger::SEV_DEBUG,
				//		"*\t%s %s (%" PRIu64 ") (%" PRIu64 ") in:%" PRIu32 " out:%" PRIu32 " tin:%lf tout:%lf tloc:%lf %%fd:%" PRIu32 " %%conns:%" PRIu32 " rest:%" PRIu64,
				//		it->second.m_comm.c_str(),
				//		(it->second.m_args.size() != 0)? it->second.m_args[0].c_str() : "",
				//		it->second.m_tid,
				//		it->second.m_refcount + 1,
				//		it->second.m_transaction_metrics.m_incoming.m_count,
				//		it->second.m_transaction_metrics.m_outgoing.m_count,
				//		((double)it->second.m_transaction_metrics.m_incoming.m_time_ns) / 1000000000,
				//		((double)it->second.m_transaction_metrics.m_outgoing.m_time_ns) / 1000000000,
				//		((double)it->second.m_transaction_processing_delay_ns) / 1000000000,
				//		it->second.m_fd_usage_ratio,
				//		it->second.m_connection_queue_usage_ratio,
				//		it->second.m_rest_time_ns);
				//}

#ifndef ANALYZER_EMITS_PROGRAMS
				//
				// Has this thread been closed druring this sample?
				//
				if(it->second.m_analysis_flags & sinsp_threadinfo::AF_CLOSED)
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
#endif
			}

			//
			// Third pass of the list of threads: emit the programs
			//
#ifdef ANALYZER_EMITS_PROGRAMS
			unordered_map<string, sinsp_threadinfo*>::iterator prit;
			for(prit = m_program_table.begin(); 
				prit != m_program_table.end(); ++ prit)
			{
				//
				// If defined, emti the processes
				//
				sinsp_counter_time tot;
	
				ASSERT(prit->second->m_proc_metrics);
				prit->second->m_proc_metrics->get_total(&tot);
				ASSERT(is_eof || tot.m_time_ns % sample_duration == 0);

				if(tot.m_count != 0)
				{
					draiosproto::process* proc = m_metrics->add_processes();
					proc->set_pid(prit->second->m_pid);
					proc->set_comm(prit->second->m_comm);
					proc->set_exe(prit->second->m_exe);
					for(vector<string>::const_iterator arg_it = prit->second->m_args.begin(); 
						arg_it != prit->second->m_args.end(); ++arg_it)
					{
						proc->add_args(*arg_it);
					}

					prit->second->m_proc_metrics->to_protobuf(proc->mutable_tcounters());
					prit->second->m_proc_transaction_metrics->to_protobuf(proc->mutable_transaction_counters());

#ifdef _DEBUG
					if(prit->second->m_proc_transaction_metrics->m_incoming.m_count +
						prit->second->m_proc_transaction_metrics->m_outgoing.m_count != 0)
					{
						g_logger.format(sinsp_logger::SEV_DEBUG, 
							"\t%s %s (%" PRIu64 ") in:%" PRIu32 " out:%" PRIu32,
							prit->second->m_comm.c_str(),
							(prit->second->m_args.size() != 0)? prit->second->m_args[0].c_str() : "",
							prit->second->m_tid,
							prit->second->m_proc_transaction_metrics->m_incoming.m_count,
							prit->second->m_proc_transaction_metrics->m_outgoing.m_count);
					}
#endif // _DEBUG
				}
			}

			//
			// fourth pass: thread table cleanup
			//
			for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
				it != m_inspector->m_thread_manager->m_threadtable.end();)
			{
				//
				// Has this thread been closed druring this sample?
				//
				if(it->second.m_analysis_flags & sinsp_threadinfo::AF_CLOSED)
				{
					//
					// Yes, remove the thread from the table
					//
					m_inspector->m_thread_manager->remove_thread(it++);
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
#endif // ANALYZER_EMITS_PROGRAMS

			////////////////////////////////////////////////////////////////////////////
			// EMIT CONNECTIONS
			////////////////////////////////////////////////////////////////////////////
			g_logger.format(sinsp_logger::SEV_DEBUG, 
				"IPv4 table size:%d",
				m_inspector->m_ipv4_connections->m_connections.size());

			if(m_inspector->m_ipv4_connections->get_n_drops() != 0)
			{
				g_logger.format(sinsp_logger::SEV_ERROR, 
					"IPv4 table size:%d",
					m_inspector->m_ipv4_connections->m_connections.size());

				m_inspector->m_ipv4_connections->clear_n_drops();
			}

			unordered_map<ipv4tuple, sinsp_connection, ip4t_hash, ip4t_cmp>::iterator cit;
			for(cit = m_inspector->m_ipv4_connections->m_connections.begin(); 
				cit != m_inspector->m_ipv4_connections->m_connections.end();)
			{
				draiosproto::ipv4_connection* conn = m_metrics->add_ipv4_connections();
				draiosproto::ipv4tuple* tuple = conn->mutable_tuple();

				tuple->set_sip(cit->first.m_fields.m_sip);
				tuple->set_dip(cit->first.m_fields.m_dip);
				tuple->set_sport(cit->first.m_fields.m_sport);
				tuple->set_dport(cit->first.m_fields.m_dport);
				tuple->set_sip(cit->first.m_fields.m_sip);
				tuple->set_l4proto(cit->first.m_fields.m_l4proto);

				conn->set_spid(cit->second.m_spid);
				conn->set_stid(cit->second.m_stid);
				conn->set_dpid(cit->second.m_dpid);
				conn->set_dtid(cit->second.m_dtid);

				cit->second.m_metrics.to_protobuf(conn->mutable_counters());
				cit->second.m_transaction_metrics.to_protobuf(conn->mutable_transaction_counters());

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
					cit->second.m_transaction_metrics.clear();
					++cit;
				}
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
				ni->set_addr(v4iflist->at(k).m_addr);
				ni->set_netmask(v4iflist->at(k).m_netmask);
			}

			////////////////////////////////////////////////////////////////////////////
			// Serialize the whole crap
			////////////////////////////////////////////////////////////////////////////
			serialize(m_prev_flush_time_ns);
		}
	}

	//
	// Clear the transaction table
	//
	g_logger.format(sinsp_logger::SEV_DEBUG, 
		"# Client Transactions:%d",
		m_inspector->get_transactions()->m_n_client_transactions);
	g_logger.format(sinsp_logger::SEV_DEBUG, 
		"# Server Transactions:%d",
		m_inspector->get_transactions()->m_n_server_transactions);

	m_inspector->get_transactions()->m_n_client_transactions = 0;
	m_inspector->get_transactions()->m_n_server_transactions = 0;

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

	//
	// If there is no event, assume that this is an EOF and use the 
	// next sample event as target time
	//
	if(evt)
	{
		ts = evt->get_ts();
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
	uint16_t etype = evt->get_type();

	//
	// Check if this is an event that goes across sample boundaries
	//
	if((evt->m_tinfo->m_analysis_flags & sinsp_threadinfo::AF_PARTIAL_METRIC) != 0)
	{
		//
		// Part of this event has already been attributed to the previous sample, 
		// we just include the remaining part
		//
		evt->m_tinfo->m_analysis_flags &= ~(sinsp_threadinfo::AF_PARTIAL_METRIC);

		delta = ts - m_prev_flush_time_ns;

		//
		// if this is an IPC or sleep event, assume it's part of the rest time
		//
		if(cat.m_category == EC_IPC || cat.m_category == EC_SLEEP)
		{
			evt->m_tinfo->m_rest_time_ns += delta;
		}
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

	bool do_inc_counter = (cat.m_category != EC_PROCESSING);

	add_syscall_time(&evt->m_tinfo->m_metrics, 
		&cat,
		delta, 
		evt->get_iosize(),
		do_inc_counter);
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
		case EC_IO:
			{
				switch(cat->m_subcategory)
				{
				case sinsp_evt::SC_FILE:
					metrics->m_io_file.add(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NET:
					metrics->m_io_net.add(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_IPC:
					metrics->m_ipc.add(cnt_delta, delta);
					break;
				case sinsp_evt::SC_UNKNOWN:
				case sinsp_evt::SC_OTHER:
					metrics->m_io_other.add(cnt_delta, delta, bytes);
					break;
				case sinsp_evt::SC_NONE:
					metrics->m_io_other.add(cnt_delta, delta, bytes);
					break;
				default:
					ASSERT(false);
					metrics->m_io_other.add(cnt_delta, delta, bytes);
					break;
				}

			}
			break;
		case EC_WAIT:
			metrics->m_wait.add(cnt_delta, delta);
			break;
	}
}
