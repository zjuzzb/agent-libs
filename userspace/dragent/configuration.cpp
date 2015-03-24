#include "configuration.h"

#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/StreamCopier.h"

#include "logger.h"

#include <sys/time.h>
#include <sys/resource.h>

using namespace Poco;
using namespace Poco::Net;

volatile bool dragent_configuration::m_signal_dump = false;
volatile bool dragent_configuration::m_terminate = false;

static std::string bool_as_text(bool b)
{
	return b ? "true" : "false";
}

dragent_configuration::dragent_configuration()
{
	m_server_port = 0;
	m_transmitbuffer_size = 0;
	m_ssl_enabled = false;
	m_compression_enabled = false;
	m_emit_full_connections = false;
	m_min_file_priority = (Message::Priority) 0;
	m_min_console_priority = (Message::Priority) 0;
	m_evtcnt = 0;
	m_subsampling_ratio = 1;
	m_autodrop_enabled = false;
	m_drop_upper_threshold = 0;
	m_drop_lower_threshold = 0;
	m_autoupdate_enabled = true;
	m_print_protobuf = false;
	m_watchdog_enabled = true;
	m_watchdog_sinsp_worker_timeout_s = 0;
	m_watchdog_connection_manager_timeout_s = 0;
	m_watchdog_analyzer_tid_collision_check_interval_s = 0;
	m_watchdog_sinsp_data_handler_timeout_s = 0;
	m_watchdog_max_memory_usage_mb = 0;
	m_dirty_shutdown_report_log_size_b = 0;
	m_capture_dragent_events = false;
	m_jmx_sampling = 1;
	m_protocols_enabled = true;
	m_remotefs_enabled = false;
}

Message::Priority dragent_configuration::string_to_priority(const string& priostr)
{
	if(priostr == "error")
	{
		return Message::PRIO_ERROR;
	}
	else if(priostr == "warning")
	{
		return Message::PRIO_WARNING;
	}
	else if(priostr == "info")
	{
		return Message::PRIO_INFORMATION;
	}
	else if(priostr == "debug")
	{
		return Message::PRIO_DEBUG;
	}
	else if(priostr == "" || priostr == "none")
	{
		return (Message::Priority)-1;
	}
	else
	{
		throw sinsp_exception("invalid consolepriority. Accepted values are: 'error', 'warning', 'info' or 'debug'.");
	}
}

void dragent_configuration::init(Application* app)
{
	m_machine_id = Environment::nodeId();

	File package_dir("/opt/draios");
	if(package_dir.exists())
	{
		m_root_dir = "/opt/draios";

		//
		// Get rid of this "bin" hack asap
		//
		m_conf_file = Path(m_root_dir).append("etc").append("dragent.yaml").toString();
		m_defaults_conf_file = Path(m_root_dir).append("etc").append("dragent.default.yaml").toString();
	}
	else
	{
		m_root_dir = Path::current();
		m_conf_file = Path(m_root_dir).append("dragent.yaml").toString();
		m_defaults_conf_file = Path(m_root_dir).append("dragent.default.yaml").toString();
	}

	m_config = make_shared<yaml_configuration>(m_conf_file, m_defaults_conf_file);
	m_root_dir = m_config->get_scalar<string>("rootdir", m_root_dir);

	if(!m_config->get_scalar<string>("metricsfile", "location", "").empty())
	{
		m_metrics_dir = Path(m_root_dir).append(m_config->get_scalar<string>("metricsfile", "location", "")).toString();
	}
	
	m_log_dir = Path(m_root_dir).append(m_config->get_scalar<string>("log", "location", "logs")).toString();
	
	if(m_customer_id.empty())
	{
		m_customer_id = m_config->get_scalar<string>("customerid", "");
	}

	if(m_server_addr.empty())
	{
		m_server_addr = m_config->get_scalar<string>("collector", "collector.sysdigcloud.com");
	}

	if(m_server_port == 0)
	{
		m_server_port = m_config->get_scalar<uint16_t>("collector_port", 6666);
	}

	if(m_min_file_priority == 0)
	{
		m_min_file_priority = string_to_priority( m_config->get_scalar<string>("log", "file_priority", "info"));
	}

	if(m_min_console_priority == 0)
	{
#ifdef _DEBUG
		m_min_console_priority = string_to_priority( m_config->get_scalar<string>("log", "console_priority", "debug"));
#else
		m_min_console_priority = string_to_priority( m_config->get_scalar<string>("log", "console_priority", "info"));
#endif		
	}

	m_transmitbuffer_size = m_config->get_scalar<uint32_t>("transmitbuffer_size", DEFAULT_DATA_SOCKET_BUF_SIZE);
	m_ssl_enabled = m_config->get_scalar<bool>("ssl", true);
	m_ssl_ca_certificate = Path(m_root_dir).append(m_config->get_scalar<string>("ca_certificate", "root.cert")).toString();
	m_compression_enabled = m_config->get_scalar<bool>("compression", "enabled", true);
	m_emit_full_connections = m_config->get_scalar<bool>("emitfullconnections_enabled", false);
	m_dump_dir = m_config->get_scalar<string>("dumpdir", "/tmp/");
	m_subsampling_ratio = m_config->get_scalar<decltype(m_subsampling_ratio)>("subsampling", "ratio", 1);
	m_autodrop_enabled =  m_config->get_scalar<bool>("autodrop", "enabled", true);
	m_drop_upper_threshold = m_config->get_scalar<decltype(m_drop_upper_threshold)>("autodrop", "upper_threshold", 0);
	m_drop_lower_threshold = m_config->get_scalar<decltype(m_drop_lower_threshold)>("autodrop", "lower_threshold", 0);

	m_host_custom_name = m_config->get_scalar<string>("ui", "customname", "");
	m_host_tags = m_config->get_scalar<string>("tags", "");
	m_host_custom_map = m_config->get_scalar<string>("ui", "custommap", "");
	m_host_hidden = m_config->get_scalar<bool>("ui", "is_hidden", false);
	m_hidden_processes = m_config->get_scalar<string>("ui", "hidden_processes", "");
	m_autoupdate_enabled = m_config->get_scalar<bool>("autoupdate_enabled", true);
	m_print_protobuf = m_config->get_scalar<bool>("protobuf_print", false);
#ifdef _DEBUG
	m_watchdog_enabled = m_config->get_scalar<bool>("watchdog_enabled", false);
#else
	m_watchdog_enabled = m_config->get_scalar<bool>("watchdog_enabled", true);
#endif
	m_watchdog_sinsp_worker_timeout_s = m_config->get_scalar<decltype(m_watchdog_sinsp_worker_timeout_s)>("watchdog", "sinsp_worker_timeout_s", 60);
	m_watchdog_connection_manager_timeout_s = m_config->get_scalar<decltype(m_watchdog_connection_manager_timeout_s)>("watchdog", "connection_manager_timeout_s", 100);
	m_watchdog_analyzer_tid_collision_check_interval_s = m_config->get_scalar<decltype(m_watchdog_analyzer_tid_collision_check_interval_s)>("watchdog", "analyzer_tid_collision_check_interval_s", 600);
	m_watchdog_sinsp_data_handler_timeout_s = m_config->get_scalar<decltype(m_watchdog_sinsp_data_handler_timeout_s)>("watchdog", "sinsp_data_handler_timeout_s", 60);
	m_watchdog_max_memory_usage_mb = m_config->get_scalar<decltype(m_watchdog_max_memory_usage_mb)>("watchdog", "max_memory_usage_mb", 256);
	m_dirty_shutdown_report_log_size_b = m_config->get_scalar<decltype(m_dirty_shutdown_report_log_size_b)>("dirty_shutdown", "report_log_size_b", 30 * 1024);
	m_capture_dragent_events = m_config->get_scalar<bool>("capture_dragent_events", false);
	m_jmx_sampling = m_config->get_scalar<decltype(m_jmx_sampling)>("jmx", "sampling", 1);
	m_protocols_enabled = m_config->get_scalar<bool>("protocols", true);
	m_remotefs_enabled = m_config->get_scalar<bool>("remotefs", false);

	refresh_aws_metadata();
}

void dragent_configuration::print_configuration()
{
	for(auto item : m_config->errors())
	{
		g_log->critical(item);
	}
	g_log->information("Distribution: " + get_distribution());
	g_log->information("rootdir: " + m_root_dir);
	g_log->information("conffile: " + m_conf_file);
	g_log->information("metricsfile.location: " + m_metrics_dir);
	g_log->information("log.location: " + m_log_dir);
	g_log->information("customerid: " + m_customer_id);
	g_log->information("collector: " + m_server_addr);
	g_log->information("collector_port: " + NumberFormatter::format(m_server_port));
	g_log->information("log.file_priority: " + NumberFormatter::format(m_min_file_priority));
	g_log->information("log.console_priority: " + NumberFormatter::format(m_min_console_priority));
	g_log->information("transmitbuffer_size: " + NumberFormatter::format(m_transmitbuffer_size));
	g_log->information("ssl: " + bool_as_text(m_ssl_enabled));
	g_log->information("ca_certificate: " + m_ssl_ca_certificate);
	g_log->information("compression.enabled: " + bool_as_text(m_compression_enabled));
	g_log->information("emitfullconnections.enabled: " + bool_as_text(m_emit_full_connections));
	g_log->information("dumpdir: " + m_dump_dir);
	g_log->information("subsampling.ratio: " + NumberFormatter::format(m_subsampling_ratio));
	g_log->information("autodrop.enabled: " + bool_as_text(m_autodrop_enabled));
	g_log->information("autodrop.threshold.upper: " + NumberFormatter::format(m_drop_upper_threshold));
	g_log->information("autodrop.threshold.lower: " + NumberFormatter::format(m_drop_lower_threshold));
	g_log->information("ui.customname: " + m_host_custom_name);
	g_log->information("tags: " + m_host_tags);
	g_log->information("ui.custommap: " + m_host_custom_map);
	g_log->information("ui.is_hidden: " + m_host_hidden);
	g_log->information("ui.hidden_processes: " + m_hidden_processes);
	g_log->information("autoupdate_enabled: " + bool_as_text(m_autoupdate_enabled));
	g_log->information("protobuf_print: " + bool_as_text(m_print_protobuf));
	g_log->information("watchdog_enabled: " + bool_as_text(m_watchdog_enabled));
	g_log->information("watchdog.sinsp_worker_timeout_s: " + NumberFormatter::format(m_watchdog_sinsp_worker_timeout_s));
	g_log->information("watchdog.connection_manager_timeout_s: " + NumberFormatter::format(m_watchdog_connection_manager_timeout_s));
	g_log->information("watchdog.analyzer_tid_collision_check_interval_s: " + NumberFormatter::format(m_watchdog_analyzer_tid_collision_check_interval_s));
	g_log->information("watchdog.sinsp_data_handler_timeout_s: " + NumberFormatter::format(m_watchdog_sinsp_data_handler_timeout_s));
	g_log->information("watchdog.max.memory_usage_mb: " + NumberFormatter::format(m_watchdog_max_memory_usage_mb));
	g_log->information("dirty_shutdown.report_log_size_b: " + NumberFormatter::format(m_dirty_shutdown_report_log_size_b));
	g_log->information("capture_dragent_events: " + bool_as_text(m_capture_dragent_events));
	g_log->information("protocols: " + bool_as_text(m_protocols_enabled));
	g_log->information("remotefs: " + bool_as_text(m_remotefs_enabled));
	g_log->information("jmx.sampling: " + NumberFormatter::format(m_jmx_sampling));

	if(m_aws_metadata.m_valid)
	{
		g_log->information("AWS public-ipv4: " + NumberFormatter::format(m_aws_metadata.m_public_ipv4));
		g_log->information("AWS instance-id: " + m_aws_metadata.m_instance_id);
	}
}

void dragent_configuration::refresh_aws_metadata()
{
	try 
	{
		HTTPClientSession client("169.254.169.254", 80);
		client.setTimeout(1000000);

		{
			HTTPRequest request(HTTPRequest::HTTP_GET, "/latest/meta-data/public-ipv4");
			client.sendRequest(request);

			HTTPResponse response; 
			std::istream& rs = client.receiveResponse(response); 

			string s;
			StreamCopier::copyToString(rs, s);

#ifndef _WIN32
			struct in_addr addr;

			if(inet_aton(s.c_str(), &addr) == 0)
			{
				m_aws_metadata.m_valid = false;
				return;
			}

			m_aws_metadata.m_public_ipv4 = addr.s_addr;
#endif
		}

		{
			HTTPRequest request(HTTPRequest::HTTP_GET, "/latest/meta-data/instance-id");
			client.sendRequest(request);

			HTTPResponse response; 
			std::istream& rs = client.receiveResponse(response); 

			StreamCopier::copyToString(rs, m_aws_metadata.m_instance_id);
		}

		m_aws_metadata.m_valid = true;
	}
	catch(Poco::Exception& e)
	{
		m_aws_metadata.m_valid = false;
	}
}

bool dragent_configuration::get_memory_usage_mb(uint64_t* memory)
{
	struct rusage usage;
	if(getrusage(RUSAGE_SELF, &usage) == -1)
	{
		g_log->error(string("getrusage") + strerror(errno));
		return false;
	}

	*memory = usage.ru_maxrss / 1024;
	return true;
}

string dragent_configuration::get_distribution()
{
	string s;

	try
	{
		Poco::FileInputStream f("/etc/system-release-cpe");
		StreamCopier::copyToString(f, s);
		return s;
	}
	catch(...)
	{
	}

	try
	{
		Poco::FileInputStream f("/etc/lsb-release");
		StreamCopier::copyToString(f, s);
		return s;
	}
	catch(...)
	{
	}

	try
	{
		Poco::FileInputStream f("/etc/debian_version");
		StreamCopier::copyToString(f, s);
		return s;
	}
	catch(...)
	{
	}

	ASSERT(false);
	return s;
}
