#pragma once

//
// The main analyzer class
//
class sinsp_analyzer
{
public:
	sinsp_analyzer(sinsp* inspector);
	~sinsp_analyzer();

	void set_sample_callback(analyzer_callback_interface* cb);
	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);
	void add_syscall_time(sinsp_counters* metrics, 
		sinsp_evt::category* cat, 
		uint64_t delta, 
		uint32_t bytes, 
		bool inc_count);

	uint64_t get_last_sample_time_ns()
	{
		return m_next_flush_time_ns;
	}

private:
	//
	// Return the health score for a process
	//
	int32_t get_process_health_score(vector<pair<uint64_t,uint64_t>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	int32_t get_process_health_score_cpu(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	char* serialize_to_bytebuf(OUT uint32_t *len);
	void serialize(uint64_t ts);
	uint64_t compute_process_transaction_delay(sinsp_transaction_counters* trcounters);
	void flush(sinsp_evt* evt, uint64_t ts, bool is_eof);

	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;

	uint64_t m_prev_sample_evtnum;

	//
	// Pointer to inspector context
	//
	sinsp* m_inspector;

	//
	// This is the protobuf class that we use to pack things
	//
	draiosproto::metrics* m_metrics;
	char* m_serialization_buffer;
	uint32_t m_serialization_buffer_size;

	//
	// The callback we invoke when a sample is ready
	//
	analyzer_callback_interface* m_sample_callback;

#ifdef ANALYZER_EMITS_PROGRAMS
	//
	// The temporary table that we build while scanning the process list.
	// Each entry contains a "program", i.e. a group of processes with the same 
	// full executable path.
	//
	unordered_map<string, sinsp_threadinfo*> m_program_table;
#endif
};
