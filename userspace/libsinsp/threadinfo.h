#pragma once

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

typedef struct erase_fd_params
{
	bool m_remove_from_table;
	sinsp* m_inspector;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo* m_fdinfo;
	uint64_t m_ts;
}erase_fd_params;

//
// Information that is included only in process main threads
//
class sinsp_procinfo
{
public:
	void clear()
	{
		m_proc_metrics.clear();
		m_proc_transaction_metrics.clear();
		m_proc_transaction_processing_delay_ns = 0;
		m_connection_queue_usage_ratio = 0;
		m_fd_usage_ratio = 0;
	}

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
	uint32_t m_connection_queue_usage_ratio;
	// The ratio between open FDs and maximum available FDs fir this thread
	uint32_t m_fd_usage_ratio;
};

//
// thread info entry
//
class SINSP_PUBLIC sinsp_threadinfo
{
public:
	//
	// thread flags
	//
	enum analysis_flags
	{
	    AF_NONE = 0,
	    AF_INVALID = (1 << 0),
	    AF_PARTIAL_METRIC = (1 << 1), // Used by the event analyzer to flag that part of the last event has already been measured because the sampling time elapsed
	    AF_CLOSED = (1 << 2), // thread has been closed. It will have to be removed from the thread table.
	    AF_IS_TRANSACTION_SERVER = (1 << 3), // set if this thread serves transactions.
	};

	sinsp_threadinfo();
	void init();
	//sinsp_threadinfo(const sinsp_threadinfo &orig);
	sinsp_threadinfo(sinsp *inspector);
	~sinsp_threadinfo();
	void init(const scap_threadinfo* pi);
	string get_comm();
	string get_cwd();
	void set_args(const char* args, size_t len);
	void store_event(sinsp_evt *evt);
	bool is_lastevent_data_valid();
	void set_lastevent_data_validity(bool isvalid);
	bool is_main_thread()
	{
		return m_tid == m_pid;
	}
	sinsp_fdinfo *get_fd(int64_t fd);

	void print_on(FILE *f);

	const sinsp_counters* get_metrics();

	//
	// Core state
	//
	int64_t m_tid;  // The id of this thread
	int64_t m_pid; // The id of the process containing this thread. In single thread threads, this is equal to tid.
	string m_comm; // Command name (e.g. "top")
	string m_exe; // Full command name (e.g. "/bin/top")
	vector<string> m_args; // Command line arguments (e.g. "-d1")
	uint32_t m_flags; // The thread flags.
	uint64_t m_refcount; // When this is 0 the process can be deleted (i.e. no children)
	int64_t m_fdlimit;  // The maximum number of FDs this thread can open

	//
	// State for multi-event processing
	//
	uint8_t m_lastevent_data[SP_EVT_BUF_SIZE]; // Used by some event parsers to store the last enter event
	int64_t m_lastevent_fd;
	uint64_t m_lastevent_ts;
	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	uint64_t m_lastaccess_ts;
	sinsp_evt::category m_lastevent_category;

	//
	// Analyzer state
	//
	// Flags word used by the analysis engine.
	uint8_t m_analysis_flags;
	// If this is a process' main thread, the Number of threads that the process contains. 
	// Otherwise zero.
	uint32_t m_n_threads; 
	// If this is a process' main thread, the Number of threads that were active for 
	// this process during the last sample. Otherwise zero.
	uint32_t m_n_concurrent_transactions;
	// The analyzer metrics
	sinsp_counters m_metrics; 
	// The analyzer transaction metrics
	sinsp_transaction_counters m_transaction_metrics; 
	// The total transaction count if this is a server
	sinsp_counter_time m_total_server_transaction_counter; 
	// The delay that this thread introduced in transaction processing.
	// This is calculated by subtracting the total outgoing transaction time to
	// the total incoming transaction time.
	uint64_t m_transaction_processing_delay_ns;
	// Process-specific information
	sinsp_procinfo* m_procinfo;
	// The number of transactions that this thread is currently serving
	uint32_t m_n_active_transactions;
	// The ratio between the number of connections waiting to be served and 
	// the total connection queue length for this process.
	uint32_t m_connection_queue_usage_ratio;
	// The ratio between open FDs and maximum available FDs fir this thread
	uint32_t m_fd_usage_ratio;
	// Information about the last select/poll/epoll done by this thread:
	// duration and number of FDs that were signaled 
	uint64_t m_lastfdwait_duration_ns;
	uint64_t m_lastfdwait_nfds;

	//
	// Global state
	//
	sinsp *m_inspector;

VISIBILITY_PRIVATE
	void add_fd(int64_t fd, sinsp_fdinfo *fdinfo);
	void remove_fd(int64_t fd);
	sinsp_fdtable* get_fd_table();
	sinsp_threadinfo* get_main_thread();
	void set_cwd(const char *cwd, uint32_t cwdlen);
	sinsp_threadinfo* get_cwd_root();
	void add_all_metrics(sinsp_threadinfo* other);
	void clear_all_metrics();
	//
	// If this is a process main thread, return the health score based on the
	// process metrics
	//
	uint32_t get_process_health_score();

	//  void push_fdop(sinsp_fdop* op);
	// the queue of recent fd operations
	//  std::deque<sinsp_fdop> m_last_fdop;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable; // The fd table of this thread
	string m_cwd; // current working directory

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_evt;
	friend class sinsp_thread_manager;
};

typedef unordered_map<int64_t, sinsp_threadinfo> threadinfo_map_t;
typedef threadinfo_map_t::iterator threadinfo_map_iterator_t;


class SINSP_PUBLIC sinsp_thread_manager
{
public:
	sinsp_thread_manager(sinsp* inspector);

	sinsp_threadinfo* get_thread(int64_t tid);
	void add_thread(const sinsp_threadinfo& threadinfo);
	void remove_thread(int64_t tid);
	void remove_thread(threadinfo_map_iterator_t it);
	void remove_inactive_threads();

	uint32_t get_thread_count()
	{
		return m_threadtable.size();
	}

	void update_statistics();

	threadinfo_map_t* get_threads()
	{
		return &m_threadtable;
	}

private:
	sinsp* m_inspector;
	threadinfo_map_t m_threadtable;
	int64_t m_last_tid;
	sinsp_threadinfo* m_last_tinfo;
	uint64_t m_last_flush_time_ns;
	uint32_t m_n_drops;

	INTERNAL_COUNTER(m_failed_lookups);
	INTERNAL_COUNTER(m_cached_lookups);
	INTERNAL_COUNTER(m_non_cached_lookups);
	INTERNAL_COUNTER(m_added_threads);
	INTERNAL_COUNTER(m_removed_threads);

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp;
};
