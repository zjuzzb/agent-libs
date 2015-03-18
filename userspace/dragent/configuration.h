#pragma once

#include "main.h"

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

class aws_metadata
{
public:
	bool m_valid;
	uint32_t m_public_ipv4; // http://169.254.169.254/latest/meta-data/public-ipv4
	string m_instance_id; // http://169.254.169.254/latest/meta-data/public-ipv4
};

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
