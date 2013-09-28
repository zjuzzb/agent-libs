#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
using namespace google::protobuf::io;

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "metrics.h"
#include "draios.pb.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_time implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_time::sinsp_counter_time()
{
	clear();
}

void sinsp_counter_time::add(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count += cnt_delta;
	m_time_ns += time_delta;
}

void sinsp_counter_time::add(sinsp_counter_time* other)
{
	m_count += other->m_count;
	m_time_ns += other->m_time_ns;
}

void sinsp_counter_time::add(sinsp_counter_time_bytes* other)
{
	m_count += (other->m_count_in + other->m_count_out + other->m_count_other);
	m_time_ns += (other->m_time_ns_in + other->m_time_ns_out + other->m_time_ns_other);
}

void sinsp_counter_time::clear()
{
	m_count = 0;
	m_time_ns = 0;
}

void sinsp_counter_time::to_protobuf(draiosproto::counter_time* protobuf_msg)
{
	protobuf_msg->set_time_ns(m_time_ns);
	protobuf_msg->set_count(m_count);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_time_bidirectional implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_time_bidirectional::sinsp_counter_time_bidirectional()
{
	clear();
}

void sinsp_counter_time_bidirectional::add_in(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_in += cnt_delta;
	m_time_ns_in += time_delta;
}

void sinsp_counter_time_bidirectional::add_out(uint32_t cnt_delta, uint64_t time_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_out += cnt_delta;
	m_time_ns_out += time_delta;
}

void sinsp_counter_time_bidirectional::add(sinsp_counter_time_bidirectional* other)
{
	m_count_in += other->m_count_in;
	m_count_out += other->m_count_out;
	m_time_ns_in += other->m_time_ns_in;
	m_time_ns_out += other->m_time_ns_out;
}

void sinsp_counter_time_bidirectional::clear()
{
	m_count_in = 0;
	m_count_out = 0;
	m_time_ns_in = 0;
	m_time_ns_out = 0;
}

void sinsp_counter_time_bidirectional::to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg)
{
	protobuf_msg->set_time_ns_in(m_time_ns_in);
	protobuf_msg->set_time_ns_out(m_time_ns_out);
	protobuf_msg->set_count_in(m_count_in);
	protobuf_msg->set_count_out(m_count_out);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_bytes implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_bytes::sinsp_counter_bytes()
{
	clear();
}

void sinsp_counter_bytes::add_in(uint32_t cnt_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_in += cnt_delta;
	m_bytes_in += bytes_delta;
}

void sinsp_counter_bytes::add_out(uint32_t cnt_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_out += cnt_delta;
	m_bytes_out += bytes_delta;
}

void sinsp_counter_bytes::add(sinsp_counter_bytes* other)
{
	m_count_in += other->m_count_in;
	m_count_out += other->m_count_out;
	m_bytes_in += other->m_bytes_in;
	m_bytes_out += other->m_bytes_out;
}

void sinsp_counter_bytes::clear()
{
	m_count_in = 0;
	m_count_out = 0;
	m_bytes_in = 0;
	m_bytes_out = 0;
}

void sinsp_counter_bytes::to_protobuf(draiosproto::counter_bytes* protobuf_msg)
{
	protobuf_msg->set_bytes_in(m_bytes_in);
	protobuf_msg->set_bytes_out(m_bytes_out);
	protobuf_msg->set_count_in(m_count_in);
	protobuf_msg->set_count_out(m_count_out);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_counter_time_bytes implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_counter_time_bytes::sinsp_counter_time_bytes()
{
	clear();
}

void sinsp_counter_time_bytes::add_in(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_in += cnt_delta;
	m_time_ns_in += time_delta;
	m_bytes_in += bytes_delta;
}

void sinsp_counter_time_bytes::add_out(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_out += cnt_delta;
	m_time_ns_out += time_delta;
	m_bytes_out += bytes_delta;
}

void sinsp_counter_time_bytes::add_other(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta)
{
	ASSERT(cnt_delta <= 1);

	m_count_other += cnt_delta;
	m_time_ns_other += time_delta;
	m_bytes_other += bytes_delta;
}

void sinsp_counter_time_bytes::add(sinsp_counter_time_bytes* other)
{
	m_count_in += other->m_count_in;
	m_count_out += other->m_count_out;
	m_count_other += other->m_count_other;
	m_time_ns_in += other->m_time_ns_in;
	m_time_ns_out += other->m_time_ns_out;
	m_time_ns_other += other->m_time_ns_other;
	m_bytes_in += other->m_bytes_in;
	m_bytes_out += other->m_bytes_out;
	m_bytes_other += other->m_bytes_other;
}


void sinsp_counter_time_bytes::clear()
{
	m_count_in = 0;
	m_count_out = 0;
	m_count_other = 0;
	m_time_ns_in = 0;
	m_time_ns_out = 0;
	m_time_ns_other = 0;
	m_bytes_in = 0;
	m_bytes_out = 0;
	m_bytes_other = 0;
}

void sinsp_counter_time_bytes::to_protobuf(draiosproto::counter_time_bytes* protobuf_msg)
{
	protobuf_msg->set_time_ns_in(m_time_ns_in);
	protobuf_msg->set_time_ns_out(m_time_ns_out);
	protobuf_msg->set_time_ns_other(m_time_ns_other);
	protobuf_msg->set_count_in(m_count_in);
	protobuf_msg->set_count_out(m_count_out);
	protobuf_msg->set_count_other(m_count_other);
	protobuf_msg->set_bytes_in(m_bytes_in);
	protobuf_msg->set_bytes_out(m_bytes_out);
	protobuf_msg->set_bytes_other(m_bytes_other);
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
//	m_io.clear();
	m_io_file.clear();
	m_io_net.clear();
	m_io_other.clear();
	m_wait.clear();
	m_processing.clear();
}

void sinsp_counters::get_total(sinsp_counter_time* tot)
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
	tot->add(&m_io_file);
	tot->add(&m_io_net);
	tot->add(&m_io_other);
	tot->add(&m_wait);
	tot->add(&m_processing);
}

void sinsp_counters::add(sinsp_counters* other)
{
	m_unknown.add(&other->m_unknown);
	m_other.add(&other->m_other);
	m_file.add(&other->m_file);
	m_net.add(&other->m_net);
	m_ipc.add(&other->m_ipc);
	m_memory.add(&other->m_memory);
	m_process.add(&other->m_process);
	m_sleep.add(&other->m_sleep);
	m_system.add(&other->m_system);
	m_signal.add(&other->m_signal);
	m_user.add(&other->m_user);
	m_time.add(&other->m_time);
	m_io_file.add(&other->m_io_file);
	m_io_net.add(&other->m_io_net);
	m_io_other.add(&other->m_io_other);
	m_wait.add(&other->m_wait);
	m_processing.add(&other->m_processing);
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
//	m_io.to_protobuf(protobuf_msg->mutable_io());
	m_io_file.to_protobuf(protobuf_msg->mutable_io_file());
	m_io_net.to_protobuf(protobuf_msg->mutable_io_net());
	m_io_other.to_protobuf(protobuf_msg->mutable_io_other());
	m_wait.to_protobuf(protobuf_msg->mutable_wait());
	m_processing.to_protobuf(protobuf_msg->mutable_processing());
}

void sinsp_counters::print_on(FILE* f)
{
	sinsp_counter_time tot;

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
	m_counter.clear();
}

/*
void sinsp_transaction_counters::get_total(sinsp_counter_time* tot)
{
	tot->add(&m_incoming);
	tot->add(&m_outgoing);
}
*/

void sinsp_transaction_counters::to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg)
{
	m_counter.to_protobuf(protobuf_msg);
}

void sinsp_transaction_counters::add(sinsp_transaction_counters* other)
{
	m_counter.add(&other->m_counter);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_connection_counters implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_connection_counters::clear()
{
	m_server.clear();
	m_client.clear();
}

void sinsp_connection_counters::to_protobuf(draiosproto::connection_categories* protobuf_msg)
{
	m_server.to_protobuf(protobuf_msg->mutable_server());
	m_client.to_protobuf(protobuf_msg->mutable_client());
}
