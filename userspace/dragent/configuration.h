#pragma once

#include "main.h"
#include "logger.h"
#include "user_event.h"
#include <yaml-cpp/yaml.h>
#include <atomic>
#include <memory>

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
	yaml_configuration(const string& str) : m_root(YAML::Load(str))
	{
	}

	yaml_configuration(string&& str) : m_root(YAML::Load(std::move(str)))
	{
	}

	yaml_configuration(const string& path, const string& defaults_path)
	{
		// We cant use logging because it's not initialized yet
		File conf_file(path);
		if(conf_file.exists())
		{
			try
			{
				m_root = YAML::LoadFile(path);
			} catch ( const YAML::BadFile& ex)
			{
				m_errors.emplace_back(string("Cannot read config file: ") + path + " reason: " + ex.what());
			} catch ( const YAML::ParserException& ex)
			{
				m_errors.emplace_back(string("Cannot read config file: ") + path + " reason: " + ex.what());
			}
		}
		else
		{
			m_errors.emplace_back(string("Config file: ") + path + " does not exists");
		}

		if(defaults_path.size())
		{
			File default_conf_file(defaults_path);
			if(default_conf_file.exists())
			{
				try
				{
					m_default_root.reset(new YAML::Node(YAML::LoadFile(defaults_path)));
				} catch ( const YAML::BadFile& ex)
				{
					m_errors.emplace_back(string("Cannot read config file: ") + defaults_path + " reason: " + ex.what());
				} catch (const YAML::ParserException& ex)
				{
					m_errors.emplace_back(string("Cannot read config file: ") + defaults_path + " reason: " + ex.what());
				}
			}
			else
			{
				m_errors.emplace_back(string("Config file: ") + defaults_path + " does not exists");
			}
		}
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
			get_sequence(ret, m_root, args...);
			if(m_default_root)
			{
				get_sequence(ret, *m_default_root, args...);
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
		auto node = m_root[key];
		if (node.IsDefined())
		{
			return node.as<T>();
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
		try
		{
			auto node = m_root[key];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		} catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(string("Config file error at key: ") + key);
		}

		if(m_default_root)
		{
			try
			{
				// Redefine `node` because assignments on YAML::Node variable modifies underlying tree
				auto node = (*m_default_root)[key];
				if (node.IsDefined())
				{
					return node.as<T>();
				}
			} catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(string("Default config file error at key: ") + key);
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
		try
		{
			auto node = m_root[key][subkey];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(string("Config file error at key: ") + key + "." + subkey);
		}

		if(m_default_root)
		{
			try
			{
				// Redefine `node` because assignments on YAML::Node variable modifies underlying tree
				auto node = (*m_default_root)[key][subkey];
				if (node.IsDefined())
				{
					return node.as<T>();
				}
			}
			catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(string("Default config file error at key: ") + key + "." + subkey);
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
		for(auto item : m_root[key])
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

		if(m_default_root)
		{
			for(auto item : (*m_default_root)[key])
			{
				try
				{
					ret.push_back(item.as<T>());
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(string("Default config file error at key: ") + key);
				}
			}
		}
		return ret;
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
		for(auto item : m_root[key])
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

		if(m_default_root)
		{
			for(auto item : (*m_default_root)[key])
			{
				try
				{
					ret[item.first.as<string>()] = item.second.as<T>();
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(string("Default config file error at key: ") + key);
				}
			}
		}
		return ret;
	}

	inline const vector<string>& errors() const
	{
		return m_errors;
	}

	const YAML::Node& get_root() const
	{
		return m_root;
	}

	const std::shared_ptr<YAML::Node> get_default_root() const
	{
		if(m_default_root)
		{
			return m_default_root;
		}
		m_errors.emplace_back("Non-existing default root requested.");
		return nullptr;
	}

	void add_error(const std::string& err)
	{
		m_errors.emplace_back(err);
	}

private:
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

	YAML::Node m_root;
	std::shared_ptr<YAML::Node> m_default_root;
	mutable vector<string> m_errors;
};

namespace YAML {
	template<>
	struct convert<app_check> {
		static Node encode(const app_check& rhs);

		static bool decode(const Node& node, app_check& rhs);
	};
}

class dragent_configuration
{
public:
	dragent_configuration();

	void init(Application* app);
	void print_configuration();
	static Message::Priority string_to_priority(const string& priostr);
	static bool get_memory_usage_mb(uint64_t* memory);
	static string get_distribution();

	// Static so that the signal handler can reach it
	static volatile bool m_signal_dump;
	static volatile bool m_terminate;
	static volatile bool m_send_log_report;

	Message::Priority m_min_console_priority;
	Message::Priority m_min_file_priority;
	Message::Priority m_min_event_priority;
	bool m_curl_debug;

	string m_root_dir;
	string m_conf_file;
	shared_ptr<yaml_configuration> m_config;

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
	uint32_t m_subsampling_ratio;
	bool m_autodrop_enabled;
	uint32_t m_drop_upper_threshold;
	uint32_t m_drop_lower_threshold;
	string m_host_custom_name;
	string m_host_tags;
	string m_host_custom_map;
	bool m_host_hidden;
	string m_hidden_processes;
	bool m_autoupdate_enabled;
	bool m_print_protobuf;
	bool m_watchdog_enabled;
	uint64_t m_watchdog_sinsp_worker_timeout_s;
	uint64_t m_watchdog_connection_manager_timeout_s;
	uint64_t m_watchdog_subprocesses_logger_timeout_s;
	uint64_t m_watchdog_analyzer_tid_collision_check_interval_s;
	uint64_t m_watchdog_sinsp_data_handler_timeout_s;
	uint64_t m_watchdog_max_memory_usage_mb;
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
	bool m_agent_installed;
	bool m_ssh_enabled;
	bool m_statsd_enabled;
	unsigned m_statsd_limit;
	bool m_sdjagent_enabled;
	vector<app_check> m_app_checks;
	string m_python_binary;
	bool m_app_checks_enabled;
	uint32_t m_containers_limit;
	vector<string> m_container_patterns;
	ports_set m_known_server_ports;
	vector<uint16_t> m_blacklisted_ports;
	vector<sinsp_chisel_details> m_chisel_details;
	bool m_system_supports_containers;

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
	int m_k8s_timeout_ms;
	string m_k8s_bt_auth_token;
	int m_k8s_delegated_nodes;
	k8s_ext_list_t m_k8s_extensions;

	string m_mesos_state_uri;
	vector<string> m_marathon_uris;
	bool m_mesos_autodetect;
	int m_mesos_timeout_ms;
	bool m_mesos_follow_leader;

	bool m_falco_baselining_enabled;

	user_event_filter_t::ptr_t m_k8s_event_filter;
	user_event_filter_t::ptr_t m_docker_event_filter;

	bool m_enable_coredump;

	bool java_present()
	{
		return !m_java_binary.empty();
	}

	bool python_present()
	{
		return !m_python_binary.empty();
	}

	void refresh_aws_metadata();
	void refresh_machine_id();

private:
	inline static bool is_executable(const string& path);
	void write_statsite_configuration();
	void parse_services_file();
	void normalize_path(const std::string& file_path, std::string& normalized_path);
	void add_event_filter(user_event_filter_t::ptr_t& flt, const std::string& system, const std::string& component);
	void configure_k8s_from_env();
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
