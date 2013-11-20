#pragma once

//
// Forward declarations
//
class sinsp_counter_time_bytes;
class sinsp_procinfo;
class sinsp_counter_time_bidirectional;

namespace draiosproto
{
    class metrics;
	class time_categories;
	class counter_time;
	class counter_time_bidirectional;
	class counter_bytes;
	class counter_time_bytes;
	class transaction_categories;
	class connection_categories;
	class counter_syscall_errors;
};

//
// A super-basic counter: just 32 bit count
//
class sinsp_counter_cnt
{
public:
	sinsp_counter_cnt()
	{
		m_count = 0;
	}

	uint32_t m_count;
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
	void add(sinsp_counter_time_bidirectional* other);
	void subtract(uint32_t cnt_delta, uint64_t time_delta);
	void clear();
	void to_protobuf(draiosproto::counter_time* protobuf_msg, uint64_t tot_relevant_time_ns);

	uint32_t m_count;
	uint64_t m_time_ns;
};

//
// A bidirectional time counter
//
class sinsp_counter_time_bidirectional
{
public:
	sinsp_counter_time_bidirectional();
	void add_in(uint32_t cnt_delta, uint64_t time_delta);
	void add_out(uint32_t cnt_delta, uint64_t time_delta);
	void add_other(uint32_t cnt_delta, uint64_t time_delta);
	void add(sinsp_counter_time_bidirectional* other);
	void clear();
	void to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg);

	uint32_t m_count_in;
	uint32_t m_count_out;
	uint32_t m_count_other;
	uint64_t m_time_ns_in;
	uint64_t m_time_ns_out;
	uint64_t m_time_ns_other;
};

//
// A basic counter: bytes + count
//
class sinsp_counter_bytes
{
public:
	sinsp_counter_bytes();
	void add_in(uint32_t cnt_delta, uint32_t bytes_delta);
	void add_out(uint32_t cnt_delta, uint32_t bytes_delta);
	void add(sinsp_counter_bytes* other);
	void clear();
	void to_protobuf(draiosproto::counter_bytes* protobuf_msg);

	uint32_t m_count_in;
	uint32_t m_count_out;
	uint32_t m_bytes_in;
	uint32_t m_bytes_out;
};

//
// A time + size in bytes counter, useful for I/O metrics
//
class sinsp_counter_time_bytes
{
public:
	sinsp_counter_time_bytes();
	void add_in(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add_out(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add_other(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add(sinsp_counter_time_bytes* other);
	void add(sinsp_counter_time* other);
	void add(sinsp_counter_time_bidirectional* other, bool add_count);
	void clear();
	void to_protobuf(draiosproto::counter_time_bytes* protobuf_msg, uint64_t tot_relevant_time_ns);

	uint32_t m_count_in;
	uint32_t m_count_out;
	uint32_t m_count_other;
	uint64_t m_time_ns_in;
	uint64_t m_time_ns_out;
	uint64_t m_time_ns_other;
	uint32_t m_bytes_in;
	uint32_t m_bytes_out;
	uint32_t m_bytes_other;
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
	sinsp_counter_time_bytes m_io_file;
	sinsp_counter_time_bytes m_io_net;
	sinsp_counter_time_bytes m_io_other;
	sinsp_counter_time_bidirectional m_wait_file;
	sinsp_counter_time_bidirectional m_wait_net;
	sinsp_counter_time_bidirectional m_wait_ipc;
	sinsp_counter_time m_wait_other;
	sinsp_counter_time m_processing;

	void clear();
	void add(sinsp_counters* other);
	void get_total(sinsp_counter_time* tot);
	void to_protobuf(draiosproto::time_categories* protobuf_msg, uint64_t sample_length_ns);

	uint64_t get_total_other_time();
	uint64_t get_total_wait_time();
	uint64_t get_total_file_time();
	uint64_t get_total_net_time();
	uint64_t get_total_ipc_time();

	double get_processing_percentage();
	double get_other_percentage();
	double get_file_percentage();
	double get_net_percentage();

private:

	sinsp_counter_time m_tot_other;
	sinsp_counter_time m_tot_wait;
	sinsp_counter_time_bytes m_tot_io_file;
	sinsp_counter_time_bytes m_tot_io_net;
	sinsp_counter_time m_tot_ipc;
	sinsp_counter_time m_tot_relevant;
};

//
// Connection counters
//
class sinsp_connection_counters
{
public:
	sinsp_counter_bytes m_server;
	sinsp_counter_bytes m_client;

	void clear();
	void to_protobuf(draiosproto::connection_categories* protobuf_msg);
	void add(sinsp_connection_counters* other);
};

//
// Transaction counters (for processes, connections, etc)
//
class sinsp_transaction_counters
{
public:
	sinsp_counter_time_bidirectional m_counter;

	void clear();
	void to_protobuf(draiosproto::counter_time_bidirectional* protobuf_msg);
	void add(sinsp_transaction_counters* other);
};

//
// Error counters (for host, processes, etc)
//
class sinsp_error_counters
{
public:
	map<int32_t, sinsp_counter_cnt> m_table;

	void clear();
	void to_protobuf(draiosproto::counter_syscall_errors* protobuf_msg);
};

//
// Various metrics coming from processes, aggregated at the host level
//
class sinsp_host_metrics
{
public:
	sinsp_host_metrics();
	void clear();
	void add(sinsp_procinfo* pinfo);

	sinsp_counters m_metrics; 
	sinsp_transaction_counters m_transaction_metrics;
	uint64_t m_transaction_processing_delay_ns;
	float m_capacity_score;
	uint32_t m_n_capacity_score_entries;
	uint32_t m_connection_queue_usage_pct;
	uint32_t m_fd_usage_pct;
	sinsp_error_counters m_syscall_errors;
};
