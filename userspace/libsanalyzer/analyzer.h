#pragma once

#include <analyzer_int.h>

//
// Prototype of the callback invoked by the analyzer when a sample is ready
//
class analyzer_callback_interface
{
public:
	virtual void sinsp_analyzer_data_ready(uint64_t ts_ns, uint64_t nevts, draiosproto::metrics* metrics) = 0;
};

typedef void (*sinsp_analyzer_callback)(char* buffer, uint32_t buflen);

#ifdef HAS_ANALYZER
class sinsp_scores;
class sinsp_procfs_parser;
class sinsp_sched_analyzer;
class sinsp_sched_analyzer2;
class sinsp_delays;
class analyzer_threadtable_listener;
class sinsp_analyzer_fd_listener;
class sinsp_configuration;
class sinsp_counters;
class sinsp_analyzer_parsers;

typedef class sinsp_ipv4_connection_manager sinsp_ipv4_connection_manager;
typedef class sinsp_unix_connection_manager sinsp_unix_connection_manager;
typedef class sinsp_pipe_connection_manager sinsp_pipe_connection_manager;
typedef class sinsp_connection sinsp_connection;

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
// Description of an executed command
//
class sinsp_executed_command
{
public:
	enum flags
	{
		FL_NONE = 0,
		FL_PIPE_HEAD = 1,
		FL_PIPE_MIDDLE = 2,
		FL_PIPE_TAIL = 4,
		FL_EXCLUDED = 8,
		FL_EXEONLY = 16,
	};

	sinsp_executed_command()
	{
		m_flags = FL_NONE;
		m_count = 1;
	}

	uint32_t m_flags;
	uint64_t m_ts;
	string m_exe;
	string m_comm;
	string m_parent_comm;
	string m_cmdline;
	uint32_t m_count; // how many times this command has been repeated
};

//
// The main analyzer class
//
class SINSP_PUBLIC sinsp_analyzer
{
public:
	enum flush_flags
	{
		DF_NONE = 0,
		DF_FORCE_FLUSH,
		DF_FORCE_NOFLUSH,
		DF_FORCE_FLUSH_BUT_DONT_EMIT,
		DF_TIMEOUT,
		DF_EOF,
	};

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
	// Get and set the library configuration settings
	//
	sinsp_configuration* get_configuration();
	void set_configuration(const sinsp_configuration& configuration);

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt, flush_flags flshflags);

	void add_syscall_time(sinsp_counters* metrics,
		sinsp_evt::category* cat, 
		uint64_t delta, 
		uint32_t bytes, 
		bool inc_count);

	uint64_t get_last_sample_time_ns()
	{
		return m_next_flush_time_ns;
	}

	//
	// Connection lookup
	//
	sinsp_connection* get_connection(const ipv4tuple& tuple, uint64_t timestamp);
#ifdef HAS_UNIX_CONNECTIONS
	sinsp_connection* get_connection(const unix_tuple& tuple, uint64_t timestamp);
	sinsp_connection* get_connection(const uint64_t ino, uint64_t timestamp);
#endif
	void remove_expired_connections(uint64_t ts);

#ifdef GATHER_INTERNAL_STATS
	//
	// Get processing stats
	//
	sinsp_stats get_stats();
#endif // GATHER_INTERNAL_STATS

	//
	// The library configuration manager
	//
	sinsp_configuration* m_configuration;

	//
	// Fills the given buffer with a string contaning the memory usage report.
	// Returns the size of the string, or -1 if the given buffer is too small.
	//
	int32_t generate_memory_report(OUT char* reportbuf, uint32_t reportbuflen, bool do_complete_report = false);

	//
	// Autodrop control
	//
	void set_autodrop_enabled(bool enabled);
	void stop_dropping_mode();
	void start_dropping_mode(uint32_t sampling_ratio);
	bool driver_stopped_dropping();

VISIBILITY_PRIVATE
	void filter_top_programs(unordered_map<size_t, sinsp_threadinfo*>* progtable, bool cs_only, uint32_t howmany);
	void filter_top_noncs_programs(unordered_map<size_t, sinsp_threadinfo*>* progtable);
	void filter_top_cs_programs(unordered_map<size_t, sinsp_threadinfo*>* progtable);
	char* serialize_to_bytebuf(OUT uint32_t *len, bool compressed);
	void serialize(sinsp_evt* evt, uint64_t ts);
	void emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof, sinsp_analyzer::flush_flags flshflags);
	void emit_aggregated_connections();
	void emit_full_connections();
	void emit_top_files();
	void tune_drop_mode(flush_flags flshflags, double treshold_metric);
	void flush(sinsp_evt* evt, uint64_t ts, bool is_eof, flush_flags flshflags);
	void add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat);
	void emit_executed_commands();

	uint32_t m_n_flushes;
	uint64_t m_next_flush_time_ns;
	uint64_t m_prev_flush_time_ns;

	uint64_t m_prev_sample_evtnum;
	uint64_t m_serialize_prev_sample_evtnum;
	uint64_t m_serialize_prev_sample_time;
	
	sinsp_analyzer_parsers* m_parser;

	//
	// Tables
	//
	sinsp_transaction_table* m_trans_table;
	sinsp_ipv4_connection_manager* m_ipv4_connections;
#ifdef HAS_UNIX_CONNECTIONS
	sinsp_unix_connection_manager* m_unix_connections;
#endif
#ifdef HAS_PIPE_CONNECTIONS
	sinsp_pipe_connection_manager* m_pipe_connections;
#endif

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
	FILE* m_protobuf_fp;

	//
	// The callback we invoke when a sample is ready
	//
	analyzer_callback_interface* m_sample_callback;

	//
	// State required for CPU load calculation
	//
	uint64_t m_old_global_total_jiffies;
	sinsp_procfs_parser* m_procfs_parser;
	vector<double> m_cpu_loads;
	vector<double> m_cpu_idles;
	vector<double> m_cpu_steals;
	// Sum of the cpu usage of all the processes
	double m_total_process_cpu;

	//
	// The table of aggreagted connections
	//
	unordered_map<process_tuple, sinsp_connection, process_tuple_hash, process_tuple_cmp>* m_reduced_ipv4_connections;

	//
	// The aggreagted host metrics
	//
	sinsp_host_metrics m_host_metrics;
	sinsp_counters m_host_req_metrics;

	//
	// The scheduler analyzer
	//
	sinsp_sched_analyzer2* m_sched_analyzer2;

	//
	// Thread-related state
	//
	uint32_t m_thread_memory_id;
	analyzer_threadtable_listener* m_threadtable_listener;

	//
	// FD-related state
	//
	sinsp_analyzer_fd_listener* m_fd_listener;

	//
	// Transaction-related state
	//
	set<uint64_t> m_server_programs;
	sinsp_transaction_counters m_host_transaction_counters; 
	uint64_t m_client_tr_time_by_servers;
	vector<vector<sinsp_trlist_entry>> m_host_server_transactions;
	vector<vector<sinsp_trlist_entry>> m_host_client_transactions;
	// ratio between the the transaction delay introduced by this host and the delay 
	// caused by the next tiers.
	//float m_local_remote_ratio;
	// Network I/O info for the whole host.
	// We calculate this separately because we want to exclude intra-host traffic
	sinsp_counter_time_bytes m_io_net;
	sinsp_delays_info* m_host_transaction_delays;
	// Timestamps the last time transaction delays
	uint64_t m_last_transaction_delays_update_time;

	//
	// Support for delay calculation
	//
	sinsp_delays* m_delay_calculator;

	//
	// Command list
	//
	vector<sinsp_executed_command> m_executed_commands;

	//
	// Subsampling-related stuff
	//
	bool m_is_sampling;
	bool m_driver_stopped_dropping;
	uint32_t m_sampling_ratio;
	uint64_t m_last_dropmode_switch_time;
	uint32_t m_seconds_above_thresholds;
	uint32_t m_seconds_below_thresholds;
	int m_mypid;
	double m_my_cpuload;
	double m_last_system_cpuload;

	friend class sinsp_transaction_table;
	friend class sinsp_scores;
	friend class sinsp_sched_analyzer2;
	friend class sinsp_delays;
	friend class sinsp_evt;
	friend class sinsp_threadinfo;
	friend class sinsp_transaction_manager;
	friend class sinsp_partial_transaction;
	friend class sinsp_fdtable;
	friend class sinsp_thread_manager;
	friend class thread_analyzer_info;
	friend class sinsp_analyzer_fd_listener;
	friend class analyzer_threadtable_listener;
	friend class sinsp_sched_analyzer;
	friend class sinsp_analyzer_parsers;
};

#endif // HAS_ANALYZER

