#ifdef HAS_ANALYZER

#pragma once

//
// Delays info
// XXX this is a temporary place for these classes
//
class sinsp_percpu_delays
{
public:
	void clear()
	{
		m_last_server_transaction_union.clear();
		m_last_client_transaction_union.clear();
	}

	vector<sinsp_trlist_entry> m_last_server_transaction_union;
	vector<sinsp_trlist_entry> m_last_client_transaction_union;
	uint64_t m_merged_server_delay;
	uint64_t m_merged_client_delay;
};

class sinsp_delays_info
{
public:
	void clear()
	{
		m_merged_server_delay = 0;
		m_merged_client_delay = 0;
	}

	vector<sinsp_percpu_delays> m_last_percpu_delays;
	double m_local_remote_ratio;
	uint64_t m_merged_server_delay;
	uint64_t m_merged_client_delay;
	int64_t m_local_processing_delay_ns;
};

///////////////////////////////////////////////////////////////////////////////
// Information that is included only in processes that are main threads
///////////////////////////////////////////////////////////////////////////////
class sinsp_procinfo
{
public:
	void clear();
	uint64_t get_tot_cputime();

	// Aggreaged metrics for the process.
	// This field is allocated only for process main threads.
	sinsp_counters m_proc_metrics; 
	// Aggreaged transaction metrics for the process.
	// This field is allocated only for process main threads.
	sinsp_transaction_counters m_proc_transaction_metrics;
	// The delay that this thread introduced in transaction processing.
	// This is calculated by subtracting the total outgoing transaction time to
	// the total incoming transaction time.
	uint64_t m_proc_transaction_processing_delay_ns;
	// The ratio between the number of connections waiting to be served and 
	// the total connection queue length for this process.
	uint32_t m_connection_queue_usage_pct;
	// The ratio between open FDs and maximum available FDs fir this thread
	uint32_t m_fd_usage_pct;
	// Syscall error table
	sinsp_error_counters m_syscall_errors;
	// the process capcity score calculated with our secret sauce algorithms
	float m_capacity_score;
	// the process capacity stolen by CPU steal time, calculated with our secret sauce algorithms
	float m_stolen_capacity_score;
	// the process CPU load
	int32_t m_cpuload;
	// the process resident memory
	int64_t m_resident_memory_kb;
	// Time spent by this thread on each of the CPUs
	vector<uint64_t> m_cpu_time_ns;
	// list of processes that are part of this program
#ifdef ANALYZER_EMITS_PROGRAMS
	vector<int64_t> m_program_pids;
#endif
	// Completed transactions lists
	vector<vector<sinsp_trlist_entry>> m_server_transactions_per_cpu;
	vector<vector<sinsp_trlist_entry>> m_client_transactions_per_cpu;
	// Number of child threads or processes that served transactions
	uint64_t m_n_transaction_threads;

	sinsp_delays_info m_transaction_delays;
};

///////////////////////////////////////////////////////////////////////////////
// Thread-related analyzer state
///////////////////////////////////////////////////////////////////////////////
class thread_analyzer_info
{
public:
	//
	// thread flags
	//
	enum flags
	{
	    AF_NONE = 0,
	    AF_INVALID = (1 << 0),
	    AF_PARTIAL_METRIC = (1 << 1), // Used by the event analyzer to flag that part of the last event has already been measured because the sampling time elapsed
	    AF_IS_IPV4_SERVER = (1 << 2), // set if this thread serves IPv4 transactions.
	    AF_IS_UNIX_SERVER = (1 << 3), // set if this thread serves unix transactions.
	    AF_IS_IPV4_CLIENT = (1 << 4), // set if this thread creates IPv4 transactions.
	    AF_IS_UNIX_CLIENT = (1 << 5), // set if this thread creates unix transactions.
	};

	void init(sinsp *inspector, sinsp_threadinfo* tinfo);
	void destroy();
	const sinsp_counters* get_metrics();
	void allocate_procinfo_if_not_present();
	void propagate_flag_bidirectional(flags flag, thread_analyzer_info* other);
	void add_all_metrics(thread_analyzer_info* other);
	void clear_all_metrics();
	void flush_inactive_transactions(uint64_t sample_end_time, uint64_t sample_duration);
	void add_completed_server_transaction(sinsp_partial_transaction* tr, bool isexternal);
	void add_completed_client_transaction(sinsp_partial_transaction* tr, bool isexternal);
	bool is_main_program_thread();
	sinsp_threadinfo* get_main_program_thread();

	// Global state
	sinsp *m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_threadinfo* m_tinfo;

	// Flags word used by the analysis engine.
	uint8_t m_th_analysis_flags;
	// The analyzer metrics
	sinsp_counters m_metrics; 
	// The transaction metrics
	sinsp_transaction_counters m_transaction_metrics; 
	// The metrics for transaction coming from the external world
	sinsp_transaction_counters m_external_transaction_metrics; 
	// The delay that this thread introduced in transaction processing.
	// This is calculated by subtracting the total outgoing transaction time to
	// the total incoming transaction time.
	//uint64_t m_transaction_processing_delay_ns;
	// Process-specific information
	sinsp_procinfo* m_procinfo;
	// The ratio between the number of connections waiting to be served and 
	// the total connection queue length for this process.
	uint32_t m_connection_queue_usage_pct;
	// This is used for CPU load calculation
	uint64_t m_old_proc_jiffies;
	// the process CPU load
	int32_t m_cpuload;
	// the process resident memory
	int64_t m_resident_memory_kb;
	// Time spent by this process on each of the CPUs
	vector<uint64_t>* m_cpu_time_ns;
	// Time and duration of the last select, poll or epoll
	uint64_t m_last_wait_end_time_ns;
	int64_t m_last_wait_duration_ns;
};

///////////////////////////////////////////////////////////////////////////////
// Thread table changes listener
///////////////////////////////////////////////////////////////////////////////
class analyzer_threadtable_listener : public sinsp_threadtable_listener
{
public:
	analyzer_threadtable_listener(sinsp* inspector, sinsp_analyzer* analyzer);
	void on_thread_created(sinsp_threadinfo* tinfo);
	void on_thread_destroyed(sinsp_threadinfo* tinfo);

private:
	sinsp* m_inspector; 
	sinsp_analyzer* m_analyzer;
};

#endif // HAS_ANALYZER
