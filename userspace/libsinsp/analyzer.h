#pragma once

class sinsp_scores;
class sinsp_procfs_parser;
class sinsp_sched_analyzer;
class sinsp_sched_analyzer2;

//
// Aggregated connection table: entry and hashing infrastructure
//
typedef union _process_tuple
{
	struct 
	{
		uint64_t m_spid;
		uint64_t m_dpid;
		uint32_t m_sip;
		uint32_t m_dip;
		uint16_t m_sport;
		uint16_t m_dport;
		uint8_t m_l4proto;
	}m_fields;
	uint8_t m_all[29];
}process_tuple;

struct process_tuple_hash
{
	size_t operator()(process_tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;
		std::hash<uint32_t> hasher32;
		std::hash<uint8_t> hasher8;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)t.m_all + 8) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)t.m_all + 16) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher32(*(uint32_t*)(t.m_all + 24)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher8(*(uint8_t*)(t.m_all + 28)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct process_tuple_cmp
{
	bool operator () (process_tuple t1, process_tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

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
	// Called by the engine after opening the event source and before 
	// receiving the first event. Can be used to make adjustments based on
	// the user's changes to the configuration.
	//
	void on_capture_start();

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

VISIBILITY_PRIVATE
	char* serialize_to_bytebuf(OUT uint32_t *len, bool compressed);
	void serialize(uint64_t ts);
	uint64_t compute_thread_transaction_delay(sinsp_transaction_counters* trcounters);
	void compute_host_transaction_delay();
	void emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof);
	void emit_aggregated_connections();
	void emit_full_connections();
	void flush(sinsp_evt* evt, uint64_t ts, bool is_eof);

	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;

	uint64_t m_prev_sample_evtnum;

	//
	// Pointer to context that we use frequently
	//
	sinsp* m_inspector;
	const scap_machine_info* m_machine_info;

	//
	// The score calculation class
	//
	sinsp_scores* m_score_calculator;

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

	//
	// State required for CPU load calculation
	//
	uint64_t m_old_global_total_jiffies;
	sinsp_procfs_parser* m_procfs_parser;
	vector<uint32_t> m_cpu_loads;
	vector<uint32_t> m_cpu_idles;

	//
	// The table of aggreagted connections
	//
	sinsp_ipv4_connection_manager m_aggregated_ipv4_table;
	unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp> m_reduced_ipv4_connections;

	//
	// The aggreagted host metrics
	//
	sinsp_host_metrics m_host_metrics;

	//
	// The scheduler analyzer
	//
	sinsp_sched_analyzer* m_sched_analyzer;
	sinsp_sched_analyzer2* m_sched_analyzer2;

	//
	// Transaction-related state
	//
	sinsp_transaction_counters m_host_transaction_metrics; 
	vector<pair<uint64_t,pair<uint64_t, uint16_t>>> m_transactions_with_cpu;
//	vector<vector<pair<uint64_t, uint64_t>>> m_server_transactions_per_cpu;
	vector<vector<sinsp_trlist_entry>> m_server_transactions_per_cpu;
	uint64_t m_client_tr_time_by_servers;
	int64_t m_host_transaction_delay_ns;
	// ratio between the the transaction delay introduced by this host and the delay 
	// caused by the next tiers. Calculated by the score
	float m_local_remote_ratio;
	// Network I/O infor for the whole host.
	// We calculate this separately because we want to exclude intra-host traffic
	sinsp_counter_time_bytes m_io_net;

	friend class sinsp_transaction_table;
	friend class sinsp_scores;
	friend class sinsp_sched_analyzer2;
};
