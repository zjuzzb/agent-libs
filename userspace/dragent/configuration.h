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
#define MAX_SAMPLE_STORE_SIZE	30

class aws_metadata
{
public:
	uint32_t m_public_ipv4; // http://169.254.169.254/latest/meta-data/public-ipv4 
};

class dragent_configuration
{
public:
	dragent_configuration();

	void init(Application* app);
	void print_configuration();
	static Message::Priority string_to_priority(const string& priostr);
	static bool get_aws_metadata(aws_metadata* metadata);
	static uint64_t get_current_time_ns();

	// Static so that the signal handler can reach it
	static volatile bool m_dump_enabled;
	static volatile bool m_terminate;

	bool m_daemon;
	Message::Priority m_min_console_priority;
	Message::Priority m_min_file_priority;
	string m_root_dir;
	string m_metrics_dir;
	string m_log_dir;
	string m_customer_id;
	string m_machine_id;
	string m_server_addr;
	uint16_t m_server_port;
	uint32_t m_transmitbuffer_size;
	bool m_dropping_mode;
	bool m_ssl_enabled;
	string m_ssl_ca_certificate;
	bool m_compression_enabled;
	bool m_emit_full_connections;
	string m_dump_file;
	string m_input_filename;
	uint64_t m_evtcnt;	
};
