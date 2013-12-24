#pragma once

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

class sinsp_delays_info;


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
	    AF_CLOSED = (1 << 2), // thread has been closed. It will have to be removed from the thread table.
	    AF_IS_IPV4_SERVER = (1 << 3), // set if this thread serves IPv4 transactions.
	    AF_IS_UNIX_SERVER = (1 << 4), // set if this thread serves unix transactions.
	    AF_IS_IPV4_CLIENT = (1 << 5), // set if this thread creates IPv4 transactions.
	    AF_IS_UNIX_CLIENT = (1 << 6), // set if this thread creates unix transactions.
	    AF_INCLUDE_INFO_IN_PROTO = (1 << 7), // In order to minimize network bw uitilization, we emit process information in the protocol only when the process is
											 // detected, and then at regular intervals. This flag controls that behavior.
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

	// Global state
	sinsp *m_inspector;
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
	// The ratio between open FDs and maximum available FDs fir this thread
	uint32_t m_fd_usage_pct;
	// This is used for CPU load calculation
	uint64_t m_old_proc_jiffies;
	// the process CPU load
	int32_t m_cpuload;
	// the process resident memory
	int64_t m_resident_memory_kb;
	// Time spent by this process on each of the CPUs
	vector<uint64_t> m_cpu_time_ns;
	// Time and duration of the last select, poll or epoll
	uint64_t m_last_wait_end_time_ns;
	int64_t m_last_wait_duration_ns;
};

///////////////////////////////////////////////////////////////////////////////
// thread info entry
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_threadinfo
{
public:
	enum flags
	{
	    TF_NONE = 0,
	    TF_NAME_CHANGED = (1 << 0),
	};

	sinsp_threadinfo();
	void init();
	//sinsp_threadinfo(const sinsp_threadinfo &orig);
	sinsp_threadinfo(sinsp *inspector);
	~sinsp_threadinfo();
	void init(const scap_threadinfo* pi);
	string get_comm();
	string get_exe();
	string get_cwd();
	void set_args(const char* args, size_t len);
	void store_event(sinsp_evt *evt);
	bool is_lastevent_data_valid();
	void set_lastevent_data_validity(bool isvalid);
	bool is_main_thread();
	sinsp_threadinfo* get_main_thread();
	sinsp_fdinfo *get_fd(int64_t fd);
#ifdef HAS_ANALYZER
	bool is_main_program_thread();
	sinsp_threadinfo* get_main_program_thread();
#endif

	void print_on(FILE *f);

	//
	// Core state
	//
	int64_t m_tid;  // The id of this thread
	int64_t m_pid; // The id of the process containing this thread. In single thread threads, this is equal to tid.
	int64_t m_ptid; // The id of the process that started this thread.
	int64_t m_progid; // Main program id. If this process is part of a logical group of processes (e.g. it's one of the apache processes), the tid of the process that is the head of this group.
	string m_comm; // Command name (e.g. "top")
	string m_exe; // Full command name (e.g. "/bin/top")
	vector<string> m_args; // Command line arguments (e.g. "-d1")
	uint32_t m_flags; // The thread flags.
	int64_t m_fdlimit;  // The maximum number of FDs this thread can open
	uint32_t m_uid; // user id
	uint32_t m_gid; // group id
	uint64_t m_nchilds; // When this is 0 the process can be deleted

	//
	// State for multi-event processing
	//
	uint8_t m_lastevent_data[SP_EVT_BUF_SIZE]; // Used by some event parsers to store the last enter event
	int64_t m_lastevent_fd;
	uint64_t m_lastevent_ts;	// timestamp of the last event for this thread
	uint64_t m_prevevent_ts;	// timestamp of the event before the last for this thread
	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	uint64_t m_lastaccess_ts;
	sinsp_evt::category m_lastevent_category;

	thread_analyzer_info* m_ainfo;

#ifdef HAS_FILTERING
	//
	// State for filtering
	//
	uint64_t m_last_latency_entertime;
	uint64_t m_latency;
#endif

	//
	// Global state
	//
	sinsp *m_inspector;

VISIBILITY_PRIVATE
	void fix_sockets_coming_from_proc();
	void add_fd(int64_t fd, sinsp_fdinfo *fdinfo);
	void remove_fd(int64_t fd);
	sinsp_fdtable* get_fd_table();
	void set_cwd(const char *cwd, uint32_t cwdlen);
	sinsp_threadinfo* get_cwd_root();
	void allocate_private_state();

	//  void push_fdop(sinsp_fdop* op);
	// the queue of recent fd operations
	//  std::deque<sinsp_fdop> m_last_fdop;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable; // The fd table of this thread
	string m_cwd; // current working directory
	sinsp_threadinfo* m_main_thread;
	sinsp_threadinfo* m_main_program_thread;
	vector<void*> m_private_state;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_evt;
	friend class sinsp_thread_manager;
	friend class sinsp_transaction_table;
	friend class thread_analyzer_info;
};

typedef unordered_map<int64_t, sinsp_threadinfo> threadinfo_map_t;
typedef threadinfo_map_t::iterator threadinfo_map_iterator_t;


///////////////////////////////////////////////////////////////////////////////
// Little class that manages the allocation of private state in the thread info class
///////////////////////////////////////////////////////////////////////////////
class sinsp_thread_privatestate_manager
{
public:
	//
	// The return value is the ID of the newly reserved memory area
	//
	uint32_t reserve(uint32_t size)
	{
		m_memory_sizes.push_back(size);
		return m_memory_sizes.size() - 1;
	}

	uint32_t get_size()
	{
		return m_memory_sizes.size();
	}

private:
	vector<uint32_t> m_memory_sizes;

	friend class sinsp_threadinfo;
};

///////////////////////////////////////////////////////////////////////////////
// This class manages the thread table
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager
{
public:
	sinsp_thread_manager(sinsp* inspector);

	sinsp_threadinfo* get_thread(int64_t tid);
	void add_thread(sinsp_threadinfo& threadinfo, bool from_scap_proctable=false);
	void remove_thread(int64_t tid);
	void remove_thread(threadinfo_map_iterator_t it);
	void remove_inactive_threads();
	void fix_sockets_coming_from_proc();

	uint32_t get_thread_count()
	{
		return m_threadtable.size();
	}

	void update_statistics();

	threadinfo_map_t* get_threads()
	{
		return &m_threadtable;
	}

	set<uint16_t> m_server_ports;

private:
	void increment_mainthread_childcount(sinsp_threadinfo* threadinfo);
	void increment_program_childcount(sinsp_threadinfo* threadinfo);
	// Don't set level, it's for internal use
	void decrement_program_childcount(sinsp_threadinfo* threadinfo, uint32_t level = 0);

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
