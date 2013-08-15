#pragma once

class sinsp_counter_with_size;
namespace draiosproto
{
    class metrics;
	class time_categories;
	class counter;
};

class sinsp_counter_basic
{
public:
	sinsp_counter_basic();
	void add(uint32_t cnt_delta, uint64_t time_delta);
	void add(sinsp_counter_basic* other);
	void add(sinsp_counter_with_size* other);
	void clear();
	void to_protobuf(draiosproto::counter* protobuf_msg);

	uint32_t m_count;
	uint64_t m_time_ns;
};

class sinsp_counter_with_size
{
public:
	sinsp_counter_with_size();
	void add(uint32_t cnt_delta, uint64_t time_delta, uint32_t bytes_delta);
	void add(sinsp_counter_with_size* other);
	void clear();
	void to_protobuf(draiosproto::counter* protobuf_msg);

	uint32_t m_count;
	uint64_t m_time_ns;
	uint32_t m_bytes;
};

class sinsp_counters
{
public:
	sinsp_counter_basic m_unknown;
	sinsp_counter_basic m_other;
	sinsp_counter_basic m_file;
	sinsp_counter_basic m_net;
	sinsp_counter_basic m_ipc;
	sinsp_counter_basic m_memory;
	sinsp_counter_basic m_process;
	sinsp_counter_basic m_sleep;
	sinsp_counter_basic m_system;
	sinsp_counter_basic m_signal;
	sinsp_counter_basic m_user;
	sinsp_counter_basic m_time;
	sinsp_counter_with_size m_io;
//	sinsp_counter_with_size m_io_file;
//	sinsp_counter_with_size m_io_net;
//	sinsp_counter_with_size m_io_other;
	sinsp_counter_basic m_wait;
	sinsp_counter_basic m_processing;

	void clear();
	void get_total(sinsp_counter_basic* tot);
	void to_protobuf(draiosproto::time_categories* protobuf_msg);
	void print_on(FILE* f);
};

class sinsp_analyzer
{
public:
	sinsp_analyzer(sinsp* inspector);
	~sinsp_analyzer();

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);
	void add_syscall_time(sinsp_counters* metrics, ppm_event_category cat, uint64_t delta, bool inc_count);

private:

	char* serialize_to_bytebuf(OUT uint32_t *len);
	void serialize_to_file(uint64_t ts);
	void flush(uint64_t ts, bool is_eof);

	//
	// Pointers to inspector context
	//
	sinsp* m_inspector;
	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;

	//
	// This is the protobuf class that we use to pack things
	//
	draiosproto::metrics* m_metrics;
	char* m_serialization_buffer;
	uint32_t m_serialization_buffer_size;
};
