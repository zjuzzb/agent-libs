#pragma once

//
// Forward declarations
//
class sinsp_counter_time_bytes;

namespace draiosproto
{
    class metrics;
	class time_categories;
	class counter;
	class transaction_categories;
	class connection_categories;
};

//
// A basic counter: total time + count
//
class sinsp_counter_time
{
public:
	sinsp_counter_time();
	void add(uint32_t cnt_delta, uint64_t time_delta);
	void add(sinsp_counter_time* other);
	void add(sinsp_counter_time_bytes* other);
	void clear();
	void to_protobuf(draiosproto::counter* protobuf_msg);

	uint32_t m_count;
	uint64_t m_time_ns;
};

//
// A basic counter: bytes + count
//
class sinsp_counter_bytes
{
public:
	sinsp_counter_bytes();
	void add(uint32_t cnt_delta, uint32_t bytes_delta);
	void add(sinsp_counter_bytes* other);
	void clear();
	void to_protobuf(draiosproto::counter* protobuf_msg);

	uint32_t m_count;
	uint32_t m_bytes;
};

//
// A basic counter + size in bytes, useful for I/O metrics
//
class sinsp_counter_time_bytes
{
public:
	sinsp_counter_time_bytes();
	void add(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add(sinsp_counter_time_bytes* other);
	void clear();
	void to_protobuf(draiosproto::counter* protobuf_msg);

	uint32_t m_count;
	uint64_t m_time_ns;
	uint32_t m_bytes;
};

//
// A collection of counters for basic operation of a process or machine
//
class sinsp_counters
{
public:
	sinsp_counter_time m_unknown;
	sinsp_counter_time m_other;
	sinsp_counter_time m_file;
	sinsp_counter_time m_net;
	sinsp_counter_time m_ipc;
	sinsp_counter_time m_memory;
	sinsp_counter_time m_process;
	sinsp_counter_time m_sleep;
	sinsp_counter_time m_system;
	sinsp_counter_time m_signal;
	sinsp_counter_time m_user;
	sinsp_counter_time m_time;
//	sinsp_counter_time_bytes m_io;
	sinsp_counter_time_bytes m_io_file;
	sinsp_counter_time_bytes m_io_net;
	sinsp_counter_time_bytes m_io_other;
	sinsp_counter_time m_wait;
	sinsp_counter_time m_processing;

	void clear();
	void add(sinsp_counters* other);
	void get_total(sinsp_counter_time* tot);
	void to_protobuf(draiosproto::time_categories* protobuf_msg);
	void print_on(FILE* f);
};

//
// Connection counters
//
class sinsp_connection_counters
{
public:
	sinsp_counter_bytes m_server_incoming;
	sinsp_counter_bytes m_server_outgoing;
	sinsp_counter_bytes m_client_incoming;
	sinsp_counter_bytes m_client_outgoing;

	void clear();
	void to_protobuf(draiosproto::connection_categories* protobuf_msg);
};

//
// Transaction counters (for processes, connections, etc)
//
class sinsp_transaction_counters
{
public:
	sinsp_counter_time m_incoming;
	sinsp_counter_time m_outgoing;

	void clear();
	void get_total(sinsp_counter_time* tot);
	void to_protobuf(draiosproto::transaction_categories* protobuf_msg);
	void add(sinsp_transaction_counters* other);
};
