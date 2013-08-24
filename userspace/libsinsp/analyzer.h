#pragma once

//
// The main analyzer class
//
class sinsp_analyzer
{
public:
	sinsp_analyzer(sinsp* inspector);
	~sinsp_analyzer();

	void set_sample_callback(sinsp_analyzer_callback cb);
	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);
	void add_syscall_time(sinsp_counters* metrics, 
		sinsp_evt::category* cat, 
		uint64_t delta, 
		uint32_t bytes, 
		bool inc_count);

private:
	char* serialize_to_bytebuf(OUT uint32_t *len);
	void serialize(uint64_t ts);
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

	//
	// The callback we invoke when a sample is ready
	//
	sinsp_analyzer_callback m_sample_callback;

#ifdef ANALYZER_EMITS_PROGRAMS
	//
	// The temporary table that we build while scanning the process list.
	// Each entry contains a "program", i.e. a group of processes with the same 
	// full executable path.
	//
	unordered_map<string, sinsp_threadinfo*> m_program_table;
#endif
};
