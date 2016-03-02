#pragma once

#include <analyzer_int.h>
#include "analyzer_utils.h"
#include <delays.h>
#include <container_analyzer.h>
#include <memory>
#include "jmx_proxy.h"
#include "statsite_proxy.h"
#include <atomic>
#include "app_checks.h"
#include <unordered_set>
#include "sinsp_curl.h"

//
// Prototype of the callback invoked by the analyzer when a sample is ready
//
class analyzer_callback_interface
{
public:
	virtual void sinsp_analyzer_data_ready(uint64_t ts_ns, uint64_t nevts, draiosproto::metrics* metrics, uint32_t sampling_ratio, double analyzer_cpu_pct, double flush_cpu_cpt, uint64_t analyzer_flush_duration_ns) = 0;
};

typedef void (*sinsp_analyzer_callback)(char* buffer, uint32_t buflen);

#ifdef HAS_ANALYZER
class sinsp_scores;
class mounted_fs;
class sinsp_procfs_parser;
class mounted_fs_proxy;
class sinsp_sched_analyzer;
class sinsp_sched_analyzer2;
class sinsp_delays;
class analyzer_threadtable_listener;
class sinsp_analyzer_fd_listener;
class sinsp_configuration;
class sinsp_counters;
class sinsp_analyzer_parsers;
class sinsp_chisel;
class sinsp_chisel_details;
class k8s;
class mesos;

typedef class sinsp_ipv4_connection_manager sinsp_ipv4_connection_manager;
typedef class sinsp_unix_connection_manager sinsp_unix_connection_manager;
typedef class sinsp_pipe_connection_manager sinsp_pipe_connection_manager;
typedef class sinsp_connection sinsp_connection;
class sinsp_connection_aggregator;
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

class self_cputime_analyzer
{
public:
	self_cputime_analyzer():
		m_index(0),
		m_previouscputime(0)
	{}
	
	void begin_flush();
	void end_flush();
	double calc_flush_percent();

private:
	static const auto LAST_SAMPLES = 10U;

	uint64_t read_cputime();
	void incr_index()
	{
		m_index = (m_index + 1) % LAST_SAMPLES;
	}

	array<uint64_t, LAST_SAMPLES> m_flushtime;
	array<uint64_t, LAST_SAMPLES> m_othertime;
	unsigned m_index;
	uint64_t m_previouscputime;
};

class sinsp_curl;

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
	// Chisel helpers
	//
	void add_chisel_dirs();
	void initialize_chisels();
	void add_chisel(sinsp_chisel* ch);
	void add_chisel(sinsp_chisel_details* cd);
	inline void add_chisel_metric(statsd_metric* metric)
	{
		m_chisel_metrics.push_back(*metric);
	}

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

	void set_is_sampling(bool is_sampling)
	{
		m_is_sampling = is_sampling;
	}
	
#ifndef _WIN32
	inline void set_jmx_iofds(const pair<FILE*, FILE*>& iofds, bool print_json)
	{
		m_jmx_proxy = make_unique<jmx_proxy>(iofds);
		m_jmx_proxy->m_print_json = print_json;
	}

	inline void set_jmx_sampling(unsigned int value)
	{
		m_jmx_sampling = value;
	}

	void set_statsd_iofds(const pair<FILE*, FILE*>& iofds);
#endif

	void set_protocols_enabled(bool value)
	{
		m_protocols_enabled = value;
	}

	void set_remotefs_enabled(bool value)
	{
		m_remotefs_enabled = value;
	}

	void set_sampling_ratio(uint64_t value)
	{
		m_sampling_ratio = (uint32_t)value;
		auto newsl = ((uint64_t) ONE_SECOND_IN_NS) / m_sampling_ratio;
		if(newsl != m_configuration->get_analyzer_sample_len_ns())
		{
			m_configuration->set_analyzer_sample_len_ns(newsl);
		}
	}

	void set_statsd_capture_localhost(bool value)
	{
#ifndef _WIN32
		m_statsd_capture_localhost.store(value, memory_order_relaxed);
#endif
	}

	void set_app_checks(const vector<app_check>& checks)
	{
		m_app_checks = checks;
		if(!m_app_checks.empty())
		{
			m_app_proxy = make_unique<app_checks_proxy>();
		}
	}

	void set_containers_limit(const uint32_t value)
	{
		m_containers_limit = std::min(value, CONTAINERS_HARD_LIMIT);
	}

	void set_container_patterns(const vector<string>& patterns)
	{
		m_container_patterns = patterns;
	}

	void set_fs_usage_from_external_proc(bool value);

VISIBILITY_PRIVATE
	typedef bool (sinsp_analyzer::*server_check_func_t)(const string&);

	void chisels_on_capture_start();
	void chisels_on_capture_end();
	void chisels_do_timeout(sinsp_evt* ev);
	template<class Iterator>
	void filter_top_programs(Iterator progtable_begin, Iterator progtable_end, bool cs_only, uint32_t howmany);
	char* serialize_to_bytebuf(OUT uint32_t *len, bool compressed);
	void serialize(sinsp_evt* evt, uint64_t ts);
	void emit_processes(sinsp_evt* evt, uint64_t sample_duration, bool is_eof, sinsp_analyzer::flush_flags flshflags);
	void flush_processes();
	void emit_aggregated_connections();
	void emit_full_connections();
	sinsp_curl* make_curl(const uri& url, long tout, std::shared_ptr<sinsp_curl::ssl> ssl = 0);
	string detect_local_server(const string& protocol, uint32_t port, server_check_func_t check_func);
	bool check_k8s_server(const string& addr);
	void init_k8s_ssl();
	k8s* make_k8s(sinsp_curl& curl, const string& k8s_api);
	k8s* get_k8s(const string& k8s_api);
	void get_k8s_data();
	void emit_k8s();
	bool check_mesos_server(const string& addr);
	mesos* make_mesos(string&& json);
	mesos* get_mesos(const string& mesos_uri);
	void get_mesos_data();
	void emit_mesos();
	void emit_top_files();
	vector<string> emit_containers(const vector<string>& active_containers);
	void emit_container(const string &container_id, unsigned* statsd_limit, uint64_t total_cpu_shares);
	void tune_drop_mode(flush_flags flshflags, double treshold_metric);
	void flush(sinsp_evt* evt, uint64_t ts, bool is_eof, flush_flags flshflags);
	void add_wait_time(sinsp_evt* evt, sinsp_evt::category* cat);
	void emit_executed_commands();
	void get_statsd();
	
#ifndef _WIN32
	static unsigned emit_statsd(const vector <statsd_metric> &statsd_metrics, draiosproto::statsd_info *statsd_info,
						   unsigned limit);
#endif
	void emit_chisel_metrics();

	uint32_t m_n_flushes;
	uint64_t m_prev_flushes_duration_ns;
	double m_prev_flush_cpu_pct;
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
	bool m_protocols_enabled;
	bool m_remotefs_enabled;

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
	// Network I/O info for the whole host.
	// We calculate this separately because we want to exclude intra-host traffic
	sinsp_counter_time_bytes m_io_net;
	sinsp_delays_info m_host_transaction_delays;

	//
	// Support for delay calculation
	//
	sinsp_delays* m_delay_calculator;

	//
	// Command list
	//
	vector<sinsp_executed_command> m_executed_commands;

	//
	// Container metrics
	//
	unordered_map<string, analyzer_container_state> m_containers;

	vector<sinsp_threadinfo*> m_threads_to_remove;

	//
	// Subsampling-related stuff
	//
	bool m_is_sampling;
	bool m_driver_stopped_dropping;
	uint32_t m_sampling_ratio;
	uint32_t m_new_sampling_ratio;
	uint64_t m_last_dropmode_switch_time;
	uint32_t m_seconds_above_thresholds;
	uint32_t m_seconds_below_thresholds;
	double m_my_cpuload;
	double m_last_system_cpuload;
	bool m_skip_proc_parsing;
	uint64_t m_prev_flush_wall_time;

	//
	// Chisel-generated metrics infrastructure
	//
	vector<sinsp_chisel*> m_chisels;
	vector<statsd_metric> m_chisel_metrics;
	bool m_run_chisels;

#ifndef _WIN32
	uint64_t m_external_command_id;
	unique_ptr<jmx_proxy> m_jmx_proxy;
	unsigned int m_jmx_sampling;
	unordered_map<int, java_process> m_jmx_metrics;
	unique_ptr<statsite_proxy> m_statsite_proxy;
	unordered_map<string, vector<statsd_metric>> m_statsd_metrics;

	atomic<bool> m_statsd_capture_localhost;
	vector<app_check> m_app_checks;
	unique_ptr<app_checks_proxy> m_app_proxy;
	decltype(m_app_proxy->read_metrics()) m_app_metrics;
	unique_ptr<mounted_fs_proxy> m_mounted_fs_proxy;
	unordered_map<string, vector<mounted_fs>> m_mounted_fs_map;
#endif

	k8s* m_k8s;
	std::shared_ptr<sinsp_curl::ssl> m_k8s_ssl;

	mesos* m_mesos;
	static bool m_mesos_bad_config;

	vector<string> m_container_patterns;
	uint32_t m_containers_limit;
	self_cputime_analyzer m_cputime_analyzer;

	//
	// KILL FLAG. IF THIS IS SET, THE AGENT WILL RESTART
	//
	bool m_die;

	friend class dragent_app;
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
	friend class k8s_ca_handler;
};

#endif // HAS_ANALYZER

