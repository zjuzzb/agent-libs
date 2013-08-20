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
#include "analyzer.h"
#include "draios.pb.h"

#define DUMP_TO_DISK

//#undef ANALYZER_SAMPLE_DURATION_NS
//#define ANALYZER_SAMPLE_DURATION_NS 5000000000


///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_basic implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_basic::sinsp_counter_basic()
{
	clear();
}

void sinsp_counter_basic::add(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count += cnt_delta;
	m_time_ns += time_delta;
}

void sinsp_counter_basic::add(sinsp_counter_basic* other)
{
	m_count += other->m_count;
	m_time_ns += other->m_time_ns;
}

void sinsp_counter_basic::add(sinsp_counter_with_size* other)
{
	m_count += other->m_count;
	m_time_ns += other->m_time_ns;
}

void sinsp_counter_basic::clear()
{
	m_count = 0;
	m_time_ns = 0;
}

void sinsp_counter_basic::to_protobuf(draiosproto::counter* protobuf_msg)
{
	protobuf_msg->set_time_ns(m_time_ns);
	protobuf_msg->set_count(m_count);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_with_size implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_with_size::sinsp_counter_with_size()
{
	clear();
}

void sinsp_counter_with_size::add(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count += cnt_delta;
	m_time_ns += time_delta;
	m_bytes += bytes_delta;
}

void sinsp_counter_with_size::add(sinsp_counter_with_size* other)
{
	m_count += other->m_count;
	m_time_ns += other->m_time_ns;
	m_bytes += other->m_bytes;
}

void sinsp_counter_with_size::clear()
{
	m_count = 0;
	m_time_ns = 0;
	m_bytes = 0;
}

void sinsp_counter_with_size::to_protobuf(draiosproto::counter* protobuf_msg)
{
	protobuf_msg->set_time_ns(m_time_ns);
	protobuf_msg->set_count(m_count);
	protobuf_msg->set_bytes(m_bytes);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counters implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_counters::clear()
{
	m_unknown.clear();
	m_other.clear();
	m_file.clear();
	m_net.clear();
	m_ipc.clear();
	m_memory.clear();
	m_process.clear();
	m_sleep.clear();
	m_system.clear();
	m_signal.clear();
	m_user.clear();
	m_time.clear();
	m_io.clear();
	m_wait.clear();
	m_processing.clear();
}

void sinsp_counters::get_total(sinsp_counter_basic* tot)
{
	tot->add(&m_unknown);
	tot->add(&m_other);
	tot->add(&m_file);
	tot->add(&m_net);
	tot->add(&m_ipc);
	tot->add(&m_memory);
	tot->add(&m_process);
	tot->add(&m_sleep);
	tot->add(&m_system);
	tot->add(&m_signal);
	tot->add(&m_user);
	tot->add(&m_time);
	tot->add(&m_io);
	tot->add(&m_wait);
	tot->add(&m_processing);
}

void sinsp_counters::to_protobuf(draiosproto::time_categories* protobuf_msg)
{
	m_unknown.to_protobuf(protobuf_msg->mutable_unknown());
	m_other.to_protobuf(protobuf_msg->mutable_other());
	m_file.to_protobuf(protobuf_msg->mutable_file());
	m_net.to_protobuf(protobuf_msg->mutable_net());
	m_ipc.to_protobuf(protobuf_msg->mutable_ipc());
	m_memory.to_protobuf(protobuf_msg->mutable_memory());
	m_process.to_protobuf(protobuf_msg->mutable_process());
	m_sleep.to_protobuf(protobuf_msg->mutable_sleep());
	m_system.to_protobuf(protobuf_msg->mutable_system());
	m_signal.to_protobuf(protobuf_msg->mutable_signal());
	m_user.to_protobuf(protobuf_msg->mutable_user());
	m_time.to_protobuf(protobuf_msg->mutable_time());
	m_io.to_protobuf(protobuf_msg->mutable_io());
	m_wait.to_protobuf(protobuf_msg->mutable_wait());
	m_processing.to_protobuf(protobuf_msg->mutable_processing());
}

void sinsp_counters::print_on(FILE* f)
{
	sinsp_counter_basic tot;

	get_total(&tot);

	//
	// tot counts the WHOLE time spent by this process in the last interval,
	// and therefore it should always be a perfect multiple of the delta time.
	// This assertion validates it.
	//
/*
	fprintf(f, "count:%" PRIu32 ", time:%.9lf\n",
		tot.m_count,
		(double)tot.m_time_ns / 1000000000);
*/		
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_transaction_counters implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_transaction_counters::clear()
{
	m_incoming.clear();
	m_outgoing.clear();
}

void sinsp_transaction_counters::get_total(sinsp_counter_basic* tot)
{
	tot->add(&m_incoming);
	tot->add(&m_outgoing);
}

void sinsp_transaction_counters::to_protobuf(draiosproto::transaction_categories* protobuf_msg)
{
	m_incoming.to_protobuf(protobuf_msg->mutable_incoming());
	m_outgoing.to_protobuf(protobuf_msg->mutable_outgoing());
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_analyzer implementation
///////////////////////////////////////////////////////////////////////////////
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

char* sinsp_analyzer::serialize_to_bytebuf(OUT uint32_t *len)
{
	//
	// Find out how many bytes we need for the serialization
	//
	*len = m_metrics->ByteSize();

	//
	// If the buffer is to small, eapnd it
	//
	if(m_serialization_buffer_size < *len)
	{
		if(*len >= MAX_SERIALIZATION_BUF_SIZE_BYTES)
		{
			g_logger.log("Metrics sample too big. Dropping it.", sinsp_logger::SEV_ERROR);
			return NULL;
		}

		m_serialization_buffer = (char*)realloc(m_serialization_buffer, *len);

		if(!m_serialization_buffer)
		{
			char *estr = g_logger.format(sinsp_logger::SEV_CRITICAL, "memory allocation error at %s:%d", 
				__FILE__, __LINE__);
			throw sinsp_exception(estr);
		}

		m_serialization_buffer_size = *len;
	}

	//
	// Do the serialization
	//
	ArrayOutputStream* array_output = new ArrayOutputStream(m_serialization_buffer, *len);
   	m_metrics->SerializeToZeroCopyStream(array_output);

	return m_serialization_buffer;
}

void sinsp_analyzer::serialize_to_file(uint64_t ts)
{
	char fname[128];
	uint32_t buflen;

	//
	// Serialize to a memory buffer
	//
	char* buf = sinsp_analyzer::serialize_to_bytebuf(&buflen);
	g_logger.format(sinsp_logger::SEV_INFO,
		"dumping metrics, ts=%" PRIu64 ", len=%" PRIu32,
		ts / 1000000000,
		buflen);

	if(!buf)
	{
		return;
	}

	//
	// Write the data to file
	//
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

void sinsp_analyzer::flush(uint64_t ts, bool is_eof)
{
	uint32_t j;
	uint64_t delta;
	ppm_event_category cat;

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

			//
			// Go though the list of threads and emit the data for each of them
			//
			threadinfo_map_iterator_t it;
			for(it = m_inspector->m_thread_manager->m_threadtable.begin(); 
				it != m_inspector->m_thread_manager->m_threadtable.end();)
			{
/*
if(it->second.m_tid == 1748)
{
	int a= 0;
}
*/
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
						cat = it->second.m_lastevent_category;
					}
					else
					{
						cat = EC_PROCESSING;
					}

					add_syscall_time(&it->second.m_metrics, 
						cat, 
						delta,
						false);

					//
					// Flag the thread so we know that part of this event has already been attributed
					//
					it->second.m_analysis_flags |= sinsp_threadinfo::AF_PARTIAL_METRIC;
				}

//if(it->second.m_tid == 4090)
//{
/*
	fprintf(stderr, "    %" PRIu64 "(%s) ",
		it->first,
		it->second.get_comm().c_str());
	it->second.m_metrics.print_on(stderr);
*/
//}
				//
				// Dump the thread info into the protobuf
				//
				sinsp_counter_basic tot;

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
				
				//
				// If this is the main thread of a process, add an entry into the processes
				// section too
				//
				if(it->second.is_main_thread())
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
				}

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
					it->second.m_metrics.clear();
					it->second.m_transaction_metrics.clear();
					++it;
				}
			}

			//
			// Go though the list of IPv4 connections and emit the data for each of them
			//
			g_logger.format(sinsp_logger::SEV_DEBUG, 
				"IPv4 table size:%d",
				m_inspector->m_ipv4_connections->m_connections.size());

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
					// Clear the connection metrics, so we're ready for the next sample
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


			//
			// Go though the list of network interfaces and emit each of them
			//
			vector<sinsp_ipv4_ifinfo>* v4iflist = m_inspector->m_network_interfaces->get_ipv4_list();
			for(uint32_t k = 0; k < v4iflist->size(); k++)
			{
				draiosproto::ipv4_network_interface* ni = m_metrics->add_ipv4_network_interfaces();

				ni->set_name(v4iflist->at(k).m_name);
				ni->set_addr(v4iflist->at(k).m_addr);
				ni->set_netmask(v4iflist->at(k).m_netmask);
			}

			//
			// Serialize the whole crap
			//
			if(m_inspector->m_configuration.get_emit_metrics_to_file())
			{
				serialize_to_file(m_prev_flush_time_ns);
			}

//			m_inspector->m_overall_metrics.print_on(stderr);
//			m_inspector->m_overall_metrics.clear();
//			fprintf(stderr, "protobuf_size: %d\n", m_metrics->ByteSize());
//			fprintf(stderr, "**********************************\n");
		}
	}

	//
	// Clear the transaction table
	//
	g_logger.format(sinsp_logger::SEV_DEBUG, 
		"Transaction table size:%d",
		m_inspector->get_transactions()->m_n_transactions);

	m_inspector->get_transactions()->m_n_transactions = 0;

	//
	// Run the periodic connection and thread table cleanup
	//
	m_inspector->remove_expired_connections(ts);
	m_inspector->m_thread_manager->remove_inactive_threads();
}

void sinsp_analyzer::process_event(sinsp_evt* evt)
{
	uint64_t ts;
	uint64_t delta;
	ppm_event_category cat;

	//
	// If there is no event, assume that this is an EOF and use the 
	// next sample event as target time
	//
	if(evt)
	{
/*
if(evt->get_num() == 3307)
{
	int a = 0;
}
*/
		ts = evt->get_ts();
	}
	else
	{
		ts = m_next_flush_time_ns;
		flush(ts, true);
		return;
	}

	//
	// Check if it's time to flush
	//
	if(ts >= m_next_flush_time_ns)
	{
		flush(ts, false);
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
	cat = evt->get_category();
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
		cat = EC_PROCESSING;
	}
	else
	{
		if(!evt->m_tinfo->is_lastevent_data_valid())
		{
			//
			// There was some kind of drop and the enter event is not matching
			//
			cat = EC_UNKNOWN;
		}

		//
		// If a sample flush happens after this event, the time will have to
		// be attributed to processing.
		//
		evt->m_tinfo->m_lastevent_category = EC_PROCESSING;
	}

	bool do_inc_counter = (cat != EC_PROCESSING);

	add_syscall_time(&evt->m_tinfo->m_metrics, cat, delta, do_inc_counter);

/*
if(do_inc_counter)
{
	fprintf(stderr, "%llu\n", evt->get_num());
}
*/
}

void sinsp_analyzer::add_syscall_time(sinsp_counters* metrics, 
									  ppm_event_category cat, 
									  uint64_t delta, 
									  bool inc_count)
{
	uint32_t cnt_delta = (inc_count)? 1 : 0;

	switch(cat)
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
		case EC_PROCESSING:
			metrics->m_processing.add(cnt_delta, delta);
			break;
		case EC_IO:
			metrics->m_io.add(cnt_delta, delta, 0);
			break;
		case EC_WAIT:
			metrics->m_wait.add(cnt_delta, delta);
			break;
	}
}
