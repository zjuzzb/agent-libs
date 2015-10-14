#pragma once

#include "main.h"
#include "logger.h"
#include <yaml-cpp/yaml.h>
#include <atomic>

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

		File default_conf_file(defaults_path);
		if(default_conf_file.exists())
		{
			try
			{
				m_default_root = YAML::LoadFile(defaults_path);
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

	/**
	* Get a scalar value from config, like:
	* customerid: "578c60dc-c8b2-11e4-a615-6c4008aec9fe"
	*/
	template<typename T>
	const T get_scalar(const string& key, const T& default_value)
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

		try
		{
			// Redefine `node` because assignments on YAML::Node variable modifies underlying tree
			auto node = m_default_root[key];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		} catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(string("Default config file error at key: ") + key);
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
	const T get_scalar(const string& key, const string& subkey, const T& default_value)
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

		try
		{
			// Redefine `node` because assignments on YAML::Node variable modifies underlying tree
			auto node = m_default_root[key][subkey];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(string("Default config file error at key: ") + key + "." + subkey);
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
	const vector<T> get_merged_sequence(const string& key)
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
		for(auto item : m_default_root[key])
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
	const unordered_map<string, T> get_merged_map(const string& key)
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
		for(auto item : m_default_root[key])
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
		return ret;
	}

	inline const vector<string>& errors() const
	{
		return m_errors;
	}

	YAML::Node m_root;

private:
	YAML::Node m_default_root;
	vector<string> m_errors;
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

	string m_root_dir;
	string m_conf_file;
	shared_ptr<yaml_configuration> m_config;

	string m_defaults_conf_file;
	string m_metrics_dir;
	string m_log_dir;
	string m_customer_id;
	string m_machine_id;
	string m_server_addr;
	uint16_t m_server_port;
	uint32_t m_transmitbuffer_size;
	bool m_ssl_enabled;
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
	bool m_remotefs_enabled;
	string m_java_binary;
	string m_sdjagent_opts;
	bool m_agent_installed;
	bool m_ssh_enabled;
	bool m_statsd_enabled;
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
