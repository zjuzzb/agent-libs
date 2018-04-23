#pragma once

#include "main.h"
#include "logger.h"
#include "user_event.h"
#include "metric_limits.h"

// suppress deprecated warnings for auto_ptr in boost
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

#include <atomic>
#include <memory>
#include <set>
#include <map>
#include <string>

///////////////////////////////////////////////////////////////////////////////
// Configuration defaults
///////////////////////////////////////////////////////////////////////////////
//
// The size of the write buffer for the socket that we use to send the data to
// the backend. If this buffer fills up, we will drop upcoming samples.
//
#define DEFAULT_DATA_SOCKET_BUF_SIZE (256 * 1024)

//
// The number of analyzer samples that we store in memory when we lose connection
// to the backend. After MAX_SAMPLE_STORE_SIZE samples, we will start dropping.
//
#define MAX_SAMPLE_STORE_SIZE 300

//
// The maximum number of policy events that can be queued for sending
// to the backend.
//
#define MAX_QUEUED_POLICY_EVENTS 500

static const int PIPE_BUFFER_SIZE = 1048576;
#define SDJAGENT_JMX_TIMEOUT "2000"

class aws_metadata
{
public:
	aws_metadata():
		m_public_ipv4(0)
	{}

	uint32_t m_public_ipv4; // http://169.254.169.254/latest/meta-data/public-ipv4
	string m_instance_id; // http://169.254.169.254/latest/meta-data/public-ipv4
};

/**
* WARNING: avoid assignment operator on YAML::Node object
* they modifies underlying tree even on const YAML::Node objects
*/
class yaml_configuration
{
public:
	// If the constructor hits an exception, set an error and let the caller handle it
	yaml_configuration(const string& str)
	{
		try
		{
			if(!add_root(YAML::Load(str)))
			{
				add_error("Cannot read config file, reason: not valid format");
			}
		}
		catch (const YAML::ParserException& ex)
		{
			m_errors.emplace_back(string("Cannot read config file, reason: ") + ex.what());
		}
	}

	yaml_configuration(string&& str)
	{
		try
		{
			if(!add_root(YAML::Load(str)))
			{
				add_error("Cannot read config file, reason: not valid format");
			}
		}
		catch (const YAML::ParserException& ex)
		{
			m_errors.emplace_back(string("Cannot read config file, reason: ") + ex.what());
		}
	}

	yaml_configuration(const initializer_list<string>& file_paths)
	{
		// We cant use logging because it's not initialized yet
		for (const auto& path : file_paths)
		{
			File conf_file(path);
			if(conf_file.exists())
			{
				try
				{
					if(!add_root(YAML::LoadFile(path)))
					{
						add_error(string("Cannot read config file: ") + path + " reason: not valid format");
					}
				}
				catch(const YAML::BadFile& ex)
				{
					m_errors.emplace_back(string("Cannot read config file: ") + path + " reason: " + ex.what());
				}
				catch(const YAML::ParserException& ex)
				{
					m_errors.emplace_back(string("Cannot read config file: ") + path + " reason: " + ex.what());
				}
			}
			else
			{
				m_warnings.emplace_back(string("Config file: ") + path + " does not exists");
			}
		}
	}

	/**
	* Will retrieve first found arbitrarily deeply nested sequence
	* into an STL container T. Also supports scalars;
	* if found entity is scalar, a container with a
	* single member is returned.
	*/
	template<typename T, typename... Args>
	T get_first_deep_sequence(Args... args)
	{
		T ret;
		try
		{
			for(const auto& root : m_roots)
			{
				get_sequence(ret, root, args...);
				if (!ret.empty())
					return ret;
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(string("Config file error."));
		}
		return ret;
	}

	/**
	* Will retrieve arbitrarily deeply nested sequence
	* into an STL container T. Also supports scalars;
	* if found entity is scalar, a container with a
	* single member is returned.
	*/
	template<typename T, typename... Args>
	T get_deep_merged_sequence(Args... args)
	{
		T ret;
		try
		{
			for(const auto& root : m_roots)
			{
				get_sequence(ret, root, args...);
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(string("Config file error."));
		}
		return ret;
	}

	/**
	* Will retrieve arbitrarily deeply nested sequence
	* into an STL container T. Also supports scalars;
	* if found entity is scalar, a container with a
	* single member is returned.
	*/
	template<typename T, typename... Args>
	static T get_deep_sequence(yaml_configuration& config, const YAML::Node& root, Args... args)
	{
		T ret;
		try
		{
			get_sequence(ret, root, args...);
		}
		catch (const YAML::BadConversion& ex)
		{
			config.add_error(string("Config file error."));
		}
		return ret;
	}

	/**
	* Get a scalar value from config, like:
	* customerid: "578c60dc-c8b2-11e4-a615-6c4008aec9fe"
	* Throws if value is not found.
	*/
	template<typename T>
	T get_scalar(const string& key)
	{
		for(const auto& root : m_roots)
		{
			auto node = root[key];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		}
		throw sinsp_exception("Entry not found: " + key);
	}

	/**
	* Get a scalar value from config, like:
	* customerid: "578c60dc-c8b2-11e4-a615-6c4008aec9fe"
	*/
	template<typename T>
	T get_scalar(const string& key, const T& default_value)
	{
		for(const auto& root : m_roots)
		{
			try
			{
				auto node = root[key];
				if (node.IsDefined())
				{
					return node.as<T>();
				}
			} catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(string("Config file error at key: ") + key);
			}
		}

		return default_value;
	}

	/**
	* Utility method to get scalar values inside a 2 level nested structure like:
	* server:
	*   address: "collector.sysdigcloud.com"
	*   port: 6666
	*
	* get_scalar<string>("server", "address", "localhost")
	*/
	template<typename T>
	T get_scalar(const string& key, const string& subkey, const T& default_value)
	{
		for(const auto& root : m_roots)
		{
			try
			{
				auto node = root[key][subkey];
				if (node.IsDefined())
				{
					return node.as<T>();
				}
			}
			catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(string("Config file error at key: ") + key + "." + subkey);
			}
		}

		return default_value;
	}

	/**
	* get data from a sequence of objects, they
	* will be merged between settings file and
	* default files, example:
	*
	* common_metrics:
	*  - cpu
	*  - memory
	*
	* get_merged_sequence<string>("common_metrics)
	*/
	template<typename T>
	vector<T> get_merged_sequence(const string& key)
	{
		vector<T> ret;
		for(const auto& root : m_roots)
		{
			for(const auto& item : root[key])
			{
				try
				{
					ret.push_back(item.as<T>());
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(string("Config file error at key ") + key);
				}
			}
		}
		return ret;
	}

	template<typename T>
	vector<T> get_merged_sequence(const string& key, vector<T> &default_value)
	{
		bool defined = false;
		vector<T> ret;
		for(const auto& root : m_roots)
		{
			auto node = root[key];
			if(node.IsDefined())
			{
				defined = true;

				for(const auto& item : node)
				{
					try
					{
						ret.push_back(item.as<T>());
					}
					catch (const YAML::BadConversion& ex)
					{
						m_errors.emplace_back(string("Config file error at key ") + key);
					}
				}
			}
		}
		if(defined)
		{
			return ret;
		}
		else
		{
			return default_value;
		}
	}

	/**
	* Get data from a map of objects, they
	* will be merged between settings and
	* default file, example:
	*
	* per_process_metrics:
	*   cassandra:
	*     - cpu
	*     - memory
	*   mongodb:
	*     - net
	*
	* get_merged_map<vector<string>>("per_process_metrics")
	*/
	template<typename T>
	unordered_map<string, T> get_merged_map(const string& key)
	{
		unordered_map<string, T> ret;
		for(auto it = m_roots.rbegin(); it != m_roots.rend(); ++it)
		{
			for(const auto& item : (*it)[key])
			{
				try
				{
					ret[item.first.as<string>()] = item.second.as<T>();
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(string("Config file error at key ") + key);
				}
			}
		}
		return ret;
	}

	inline const vector<string>& errors() const
	{
		return m_errors;
	}

	inline const vector<string>& warnings() const
	{
		return m_warnings;
	}

	void add_warning(const std::string& warning)
	{
		m_warnings.emplace_back(warning);
	}

	// WARN: when possible we should avoid using directly underlying YAML nodes
	const vector<YAML::Node>& get_roots() const
	{
		return m_roots;
	}

private:

	void add_error(const std::string& err)
	{
		m_errors.emplace_back(err);
	}

	// no-op needed to compile and terminate recursion
	template <typename T>
	static void get_sequence(T&, const YAML::Node&)
	{
	}

	// called with the last variadic arg (where the sequence is expected to be found)
	template <typename T>
	static void get_sequence(T& ret, const YAML::Node& node, const std::string& name)
	{
		YAML::Node child_node = node[name];
		if(child_node.IsDefined())
		{
			if(child_node.IsSequence())
			{
				for(const YAML::Node& item : child_node)
				{
					ret.insert(ret.end(), item.as<typename T::value_type>());
				}
			}
			else if(child_node.IsScalar())
			{
				ret.insert(ret.end(), child_node.as<typename T::value_type>());
			}
		}
	}

	template<typename T, typename... Args>
	static void get_sequence(T& ret, const YAML::Node& node, const std::string& arg1, Args... args)
	{
		YAML::Node child_node = node[arg1];
		get_sequence(ret, child_node, args...);
	}

	bool add_root(YAML::Node&& root)
	{
		if (root.IsMap())
		{
			m_roots.emplace_back(root);
			return true;
		}
		else
		{
			return false;
		}
	}

	vector<YAML::Node> m_roots;
	mutable vector<string> m_errors;
	mutable vector<string> m_warnings;
};

class dragent_configuration;

class dragent_auto_configuration
{
public:
	dragent_auto_configuration(const std::string &config_filename,
				   const std::string &config_directory,
				   const std::string &config_header);

	virtual ~dragent_auto_configuration()
	{
	};

	int save(dragent_configuration &config, const std::string &config_data, std::string &errstr);

	void init_digest();

	std::string digest();

	const std::string config_path();

	void set_config_directory(const std::string &config_directory);

	virtual bool validate(const std::string &new_config_data, std::string &errstr) = 0;

	virtual void apply(dragent_configuration &config) = 0;

protected:
	std::string m_config_filename;
	std::string m_config_directory;
	std::string m_config_header;

private:
	SHA1Engine m_sha1_engine;
	DigestEngine::Digest m_digest;
};

enum class dragent_mode_t {
	STANDARD,
	NODRIVER,
	SIMPLEDRIVER
};

class dragent_configuration
{
public:
	dragent_configuration();

	void init(Application* app, bool use_installed_dragent_yaml=true);
	void print_configuration() const;
	static Message::Priority string_to_priority(const string& priostr);
	static bool get_memory_usage_mb(uint64_t* memory);
	static string get_distribution();
	bool load_error() const { return m_load_error; }

	// Static so that the signal handler can reach it
	static std::atomic<bool> m_signal_dump;
	static std::atomic<bool> m_terminate;
	static std::atomic<bool> m_send_log_report;
	static std::atomic<bool> m_config_update;

	Message::Priority m_min_console_priority;
	Message::Priority m_min_file_priority;
	Message::Priority m_min_event_priority;
	bool m_curl_debug;

	string m_root_dir;
	string m_conf_file;
	unique_ptr<yaml_configuration> m_config;

	string m_defaults_conf_file;
	string m_metrics_dir;
	string m_log_dir;
	string m_customer_id;
	string m_machine_id;
	string m_machine_id_prefix;
	string m_server_addr;
	uint16_t m_server_port;
	uint32_t m_transmitbuffer_size;
	bool m_ssl_enabled;
	bool m_ssl_verify_certificate;
	string m_ssl_ca_certificate;
	bool m_compression_enabled;
	bool m_emit_full_connections;
	string m_dump_dir;
	string m_input_filename;
	uint64_t m_evtcnt;

	// parameters used by cpu usage tuning
	uint32_t m_subsampling_ratio;
	bool m_autodrop_enabled;
	uint32_t m_drop_upper_threshold;
	uint32_t m_drop_lower_threshold;
	long m_tracepoint_hits_threshold;
	unsigned m_tracepoint_hits_ntimes;
	double m_cpu_usage_max_sr_threshold;
	unsigned m_cpu_usage_max_sr_ntimes;

	string m_host_custom_name;
	string m_host_tags;
	string m_host_custom_map;
	bool m_host_hidden;
	string m_hidden_processes;
	bool m_autoupdate_enabled;
	bool m_print_protobuf;
	string m_json_parse_errors_logfile;
	double m_json_parse_errors_events_rate;
	uint32_t m_json_parse_errors_events_max_burst;
	bool m_watchdog_enabled;
	uint64_t m_watchdog_sinsp_worker_timeout_s;
	uint64_t m_watchdog_connection_manager_timeout_s;
	uint64_t m_watchdog_subprocesses_logger_timeout_s;
	uint64_t m_watchdog_analyzer_tid_collision_check_interval_s;
	uint64_t m_watchdog_sinsp_data_handler_timeout_s;
	uint64_t m_watchdog_max_memory_usage_mb;
	uint64_t m_watchdog_warn_memory_usage_mb;
#ifndef CYGWING_AGENT
	uint64_t m_watchdog_heap_profiling_interval_s;
#endif
	uint64_t m_dirty_shutdown_report_log_size_b;
	map<string, uint64_t> m_watchdog_max_memory_usage_subprocesses_mb;
	map<string, uint64_t> m_watchdog_subprocesses_timeout_s;
	bool m_capture_dragent_events;
	aws_metadata m_aws_metadata;
	uint16_t m_jmx_sampling;
	bool m_protocols_enabled;
	uint32_t m_protocols_truncation_size;
	bool m_remotefs_enabled;
	string m_java_binary;
	string m_sdjagent_opts;
	unsigned m_jmx_limit;
	bool m_agent_installed;
	bool m_sysdig_capture_enabled;
	uint32_t m_max_sysdig_captures;
	double m_sysdig_capture_transmit_rate;
	int32_t m_sysdig_capture_compression_level;
	bool m_statsd_enabled;
	unsigned m_statsd_limit;
	uint16_t m_statsd_port;
	bool m_sdjagent_enabled;
	vector<app_check> m_app_checks;
	string m_python_binary;
	bool m_app_checks_enabled;
	unsigned m_app_checks_limit;
	uint32_t m_containers_limit;
	uint32_t m_containers_labels_max_len;
	vector<string> m_container_patterns;
	ports_set m_known_server_ports;
	vector<uint16_t> m_blacklisted_ports;
	vector<sinsp_chisel_details> m_chisel_details;
	bool m_system_supports_containers;
#ifndef CYGWING_AGENT
	prometheus_conf m_prom_conf;
#endif

	typedef std::set<std::string>      k8s_ext_list_t;
	typedef shared_ptr<k8s_ext_list_t> k8s_ext_list_ptr_t;

	std::string m_k8s_api_server;
	bool m_k8s_autodetect;
	string m_k8s_ssl_cert_type;
	string m_k8s_ssl_cert;
	string m_k8s_ssl_key;
	string m_k8s_ssl_key_password;
	string m_k8s_ssl_ca_certificate;
	bool m_k8s_ssl_verify_certificate;
	uint64_t m_k8s_timeout_s;
	string m_k8s_bt_auth_token;
	int m_k8s_delegated_nodes = 0;
	bool m_k8s_simulate_delegation;
	k8s_ext_list_t m_k8s_extensions;
	bool m_use_new_k8s;
	std::multimap<sinsp_logger::severity, std::string> m_k8s_logs;
	std::string m_k8s_cluster_name;

	string m_mesos_state_uri;
	vector<string> m_marathon_uris;
	bool m_mesos_autodetect;
	int m_mesos_timeout_ms;
	bool m_mesos_follow_leader;
	bool m_marathon_follow_leader;
#ifndef CYGWING_AGENT
	mesos::credentials_t m_mesos_credentials;
	mesos::credentials_t m_marathon_credentials;
	mesos::credentials_t m_dcos_enterprise_credentials;
	std::set<std::string> m_marathon_skip_labels;
#endif

	bool m_falco_baselining_enabled;
	bool m_command_lines_capture_enabled;
	sinsp_configuration::command_capture_mode_t m_command_lines_capture_mode;
	set<string> m_command_lines_valid_ancestors;
	bool m_memdump_enabled;
	uint64_t m_memdump_size;

	user_event_filter_t::ptr_t m_k8s_event_filter;
	user_event_filter_t::ptr_t m_docker_event_filter;

	bool m_excess_metric_log = false;
	filter_vec_t m_metrics_filter;
	filter_vec_t m_k8s_filter;
	uint16_t m_k8s_cache_size;
	bool m_excess_k8s_log = false;
	unsigned m_metrics_cache;
	filter_vec_t m_labels_filter;
	uint16_t m_labels_cache;
	bool m_excess_labels_log = false;
	mount_points_filter_vec m_mounts_filter;
	unsigned m_mounts_limit_size;
	unsigned m_max_thread_table_size;
	bool m_enable_coredump;
	bool m_auto_config;
	bool m_emit_tracers = false;

	bool m_enable_falco_engine;
	string m_falco_default_rules_filename;
	string m_falco_fallback_default_rules_filename;
	string m_falco_auto_rules_filename;
	string m_falco_rules_filename;
	double m_falco_engine_sampling_multiplier;
	std::set<std::string> m_falco_engine_disabled_rule_patterns;

	// Set when a new auto rules file is downloaded. Monitored by
	// sinsp_agent and when set will reload the falco engine and
	// clear.
	std::atomic_bool m_reset_falco_engine;

	bool m_security_enabled;
	string m_security_policies_file;
	string m_security_baselines_file;
	uint64_t m_security_report_interval_ns;
	uint64_t m_security_throttled_report_interval_ns;
	uint64_t m_actions_poll_interval_ns;
	uint64_t m_metrics_report_interval_ns;
	double m_policy_events_rate;
	uint32_t m_policy_events_max_burst;
	bool m_security_send_monitor_events;

	uint64_t m_user_events_rate;
	uint64_t m_user_max_burst_events;
	dragent_mode_t m_mode;
	bool m_detect_stress_tools = false;
	vector<string> m_stress_tools;

	bool m_cointerface_enabled;
	uint32_t m_coclient_max_loop_evts = 100;
	bool m_swarm_enabled;

	uint64_t m_security_baseline_report_interval_ns;

	std::set<double> m_percentiles;
	static const unsigned MAX_PERCENTILES = 4;
	std::vector<double> m_ignored_percentiles;
	shared_ptr<proc_filter::group_pctl_conf> m_group_pctl_conf;

	unsigned m_snaplen;

	uint16_t m_monitor_files_freq_sec = 0;
	std::set<std::string> m_monitor_files;

	uint32_t m_orch_queue_len;
	int32_t m_orch_gc;
	uint32_t m_orch_inf_wait_time_s;
	uint32_t m_orch_tick_interval_ms;
	uint32_t m_orch_low_ticks_needed;
	uint32_t m_orch_low_evt_threshold;

	bool java_present() const
	{
		return !m_java_binary.empty();
	}

	bool python_present() const
	{
#ifndef CYGWING_AGENT
		return !m_python_binary.empty();
#else
		return false;
#endif
	}

	void refresh_aws_metadata();
	void refresh_machine_id();

	// Returns 0 if already up-to-date, 1 if updated, -1 if
	// error. On error, &errstr is updated with the source of the
	// error.
	int save_auto_config(const string &config_filename, const string& config_data, string &errstr);

	void set_auto_config_directory(const string &config_directory);

private:
	inline static bool is_executable(const string& path);
	void write_statsite_configuration();
	void normalize_path(const std::string& file_path, std::string& normalized_path);
	void add_event_filter(user_event_filter_t::ptr_t& flt, const std::string& system, const std::string& component);
	void configure_k8s_from_env();
	void add_percentiles();

	void sanitize_limits(filter_vec_t& filters);


	std::map<std::string, std::unique_ptr<dragent_auto_configuration>> m_supported_auto_configs;
	bool m_load_error;

	friend class aws_metadata_refresher;
};

class aws_metadata_refresher: public Runnable
{
public:
	aws_metadata_refresher(dragent_configuration* configuration):
		m_refreshed(false),
		m_running(false),
		m_configuration(configuration)
	{}

	void run()
	{
		m_running.store(true, memory_order_relaxed);
		m_configuration->refresh_aws_metadata();
		m_refreshed.store(true, memory_order_relaxed);
	}

	void reset()
	{
		m_running.store(false, memory_order_relaxed);
		m_refreshed.store(false, memory_order_relaxed);
	}

	bool done()
	{
		return m_refreshed.load(memory_order_relaxed);
	}

	bool is_running()
	{
		return m_running.load(memory_order_relaxed);
	}

private:
	atomic<bool> m_refreshed;
	atomic<bool> m_running;
	dragent_configuration* m_configuration;
};
