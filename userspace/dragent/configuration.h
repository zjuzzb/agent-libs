#pragma once

#include "main.h"
#include "logger.h"
#include <yaml-cpp/yaml.h>

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
#define MAX_SAMPLE_STORE_SIZE 256

class aws_metadata
{
public:
	bool m_valid;
	uint32_t m_public_ipv4; // http://169.254.169.254/latest/meta-data/public-ipv4
	string m_instance_id; // http://169.254.169.254/latest/meta-data/public-ipv4
};

class yaml_configuration
{
public:
	yaml_configuration(const string& path, const string& defaults_path)
	{
		try
		{
			m_root = YAML::LoadFile(path);
		} catch ( const YAML::BadFile& ex)
		{
#ifndef UNIT_TEST_BINARY
			g_log->critical("Cannot read config file: " + path + "reason: " + ex.what());
#endif
		}

		try
		{
			m_default_root = YAML::LoadFile(defaults_path);
		} catch ( const YAML::BadFile& ex)
		{
#ifndef UNIT_TEST_BINARY
			g_log->critical("Cannot read config file: " + defaults_path + "reason: " + ex.what());
#endif
		}
	}

	/**
	* Get a scalar value from config, like:
	* customerid: "578c60dc-c8b2-11e4-a615-6c4008aec9fe"
	*/
	template<typename T>
	const T get_scalar(const string& key, const T& default_value)
	{
		auto node = m_root[key];
		if (node.IsDefined())
		{
			return node.as<T>();
		}
		else
		{
			node = m_default_root[key];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
			else
			{
				return default_value;
			}
		}
	}

	/**
	* Utility method to get scalar values inside a 2 level nested structure like:
	* server:
	*   address: "collector.sysdigcloud.com"
	*   port: 6666
	*/
	template<typename T>
	const T get_scalar(const string& key, const string& subkey, const T& default_value)
	{
		auto node = m_root[key][subkey];
		if (node.IsDefined())
		{
			return node.as<T>();
		}
		else
		{
			node = m_default_root[key][subkey];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
			else
			{
				return default_value;
			}
		}
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
		auto node = m_default_root[key];
		for(auto item : node)
		{
			ret.push_back(item.as<T>());
		}
		node = m_root[key];
		for(auto item : node)
		{
			ret.push_back(item.as<T>());
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
		auto node = m_default_root[key];
		for(auto item : node)
		{
			ret[item.first.as<string>()] = item.second.as<T>();
		}
		node = m_root[key];
		for(auto item : node)
		{
			ret[item.first.as<string>()] = item.second.as<T>();
		}
		return ret;
	}

private:
	YAML::Node m_root;
	YAML::Node m_default_root;
};

class dragent_configuration
{
public:
	dragent_configuration();

	void init(Application* app);
	void print_configuration();
	static Message::Priority string_to_priority(const string& priostr);
	static uint64_t get_current_time_ns();
	static bool get_memory_usage_mb(uint64_t* memory);
	static string get_distribution();

	// Static so that the signal handler can reach it
	static volatile bool m_signal_dump;
	static volatile bool m_terminate;

	Message::Priority m_min_console_priority;
	Message::Priority m_min_file_priority;
	string m_root_dir;
	string m_conf_file;
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
	uint32_t m_drop_upper_treshold;
	uint32_t m_drop_lower_treshold;
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
	uint64_t m_watchdog_analyzer_tid_collision_check_interval_s;
	uint64_t m_watchdog_sinsp_data_handler_timeout_s;
	uint64_t m_watchdog_max_memory_usage_mb;
	uint64_t m_dirty_shutdown_report_log_size_b;
	bool m_capture_dragent_events;
	aws_metadata m_aws_metadata;
	uint16_t m_jmx_sampling;
	bool m_protocols_enabled;
	bool m_remotefs_enabled;

private:
	void refresh_aws_metadata();
};
