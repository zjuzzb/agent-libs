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
	m_drop_upper_treshold = 0;
	m_drop_lower_treshold = 0;
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
		m_conf_file = Path(m_root_dir).append("bin").append("dragent.properties").toString();
	}
	else
	{
		m_root_dir = Path::current();
		m_conf_file = Path(m_root_dir).append("dragent.properties").toString();
	}

	try
	{
		app->loadConfiguration(m_conf_file); 
	}
	catch(...)
	{
	}

	LayeredConfiguration& config = app->config();

	m_root_dir = config.getString("rootdir", m_root_dir);

	if(!config.getString("metricsfile.location", "").empty())
	{
		m_metrics_dir = Path(m_root_dir).append(config.getString("metricsfile.location", "")).toString();
	}
	
	m_log_dir = Path(m_root_dir).append(config.getString("logfile.location", "logs")).toString();
	
	if(m_customer_id.empty())
	{
		m_customer_id = config.getString("customerid", "");
	}

	if(m_server_addr.empty())
	{
		m_server_addr = config.getString("server.address", "collector.sysdigcloud.com");
	}

	if(m_server_port == 0)
	{
		m_server_port = config.getInt("server.port", 6666);
	}

	if(m_min_file_priority == 0)
	{
		m_min_file_priority = string_to_priority(config.getString("logpriority.file", "info"));
	}

	if(m_min_console_priority == 0)
	{
#ifdef _DEBUG
		m_min_console_priority = string_to_priority(config.getString("logpriority.console", "debug"));
#else
		m_min_console_priority = string_to_priority(config.getString("logpriority.console", "info"));
#endif		
	}

	m_transmitbuffer_size = config.getInt("transmitbuffer.size", DEFAULT_DATA_SOCKET_BUF_SIZE);
	m_ssl_enabled = config.getBool("ssl.enabled", true);
	m_ssl_ca_certificate = Path(m_root_dir).append(config.getString("ssl.ca_certificate", "root.cert")).toString();
	m_compression_enabled = config.getBool("compression.enabled", true);
	m_emit_full_connections = config.getBool("emitfullconnections.enabled", false);
	m_dump_dir = config.getString("dumpdir", "/tmp/");
	m_subsampling_ratio = config.getInt("subsampling.ratio", 1);
	m_autodrop_enabled = config.getBool("autodrop.enabled", true);
	m_drop_upper_treshold = config.getInt("autodrop.treshold.upper", 0);
	m_drop_lower_treshold = config.getInt("autodrop.treshold.lower", 0);

	m_host_custom_name = config.getString("ui.customname", "");
	m_host_tags = config.getString("ui.tags", "");
	m_host_custom_map = config.getString("ui.custommap", "");
	m_host_hidden = config.getBool("ui.is_hidden", false);
	m_hidden_processes = config.getString("ui.hidden_processes", "");
	m_autoupdate_enabled = config.getBool("autoupdate.enabled", true);
	m_print_protobuf = config.getBool("protobuf.print", false);
#ifdef _DEBUG
	m_watchdog_enabled = config.getBool("watchdog.enabled", false);
#else
	m_watchdog_enabled = config.getBool("watchdog.enabled", true);
#endif
	m_watchdog_sinsp_worker_timeout_s = config.getInt("watchdog.sinsp_worker.timeout_s", 60);
	m_watchdog_connection_manager_timeout_s = config.getInt("watchdog.connection_manager.timeout_s", 100);
	m_watchdog_analyzer_tid_collision_check_interval_s = config.getInt("watchdog.analyzer.tid_collision.check_interval_s", 600);
	m_watchdog_sinsp_data_handler_timeout_s = config.getInt("watchdog.sinsp_data_handler.timeout_s", 60);
	m_watchdog_max_memory_usage_mb = config.getInt("watchdog.max.memory_usage_mb", 256);
	m_dirty_shutdown_report_log_size_b = config.getInt("dirty_shutdown.report.log_size_b", 30 * 1024);
	m_capture_dragent_events = config.getBool("capture.dragent.events", false);
	m_jmx_sampling = config.getInt("jmx.sampling", 1);
	m_protocols_enabled = config.getBool("protocols.enabled", true);
	m_remotefs_enabled = config.getBool("remotefs.enabled", false);

	refresh_aws_metadata();
}

void dragent_configuration::print_configuration()
{
	g_log->information("Distribution: " + get_distribution());
	g_log->information("rootdir: " + m_root_dir);
	g_log->information("conffile: " + m_conf_file);
	g_log->information("metricsfile.location: " + m_metrics_dir);
	g_log->information("logfile.location: " + m_log_dir);
	g_log->information("customerid: " + m_customer_id);
	g_log->information("server.address: " + m_server_addr);
	g_log->information("server.port: " + NumberFormatter::format(m_server_port));
	g_log->information("logpriority.file: " + NumberFormatter::format(m_min_file_priority));
	g_log->information("logpriority.console: " + NumberFormatter::format(m_min_console_priority));
	g_log->information("transmitbuffer.size: " + NumberFormatter::format(m_transmitbuffer_size));
	g_log->information("ssl.enabled: " + bool_as_text(m_ssl_enabled));	
	g_log->information("ssl.ca_certificate: " + m_ssl_ca_certificate);
	g_log->information("compression.enabled: " + bool_as_text(m_compression_enabled));
	g_log->information("emitfullconnections.enabled: " + bool_as_text(m_emit_full_connections));
	g_log->information("dumpdir: " + m_dump_dir);
	g_log->information("subsampling.ratio: " + NumberFormatter::format(m_subsampling_ratio));
	g_log->information("autodrop.enabled: " + bool_as_text(m_autodrop_enabled));
	g_log->information("autodrop.treshold.upper: " + NumberFormatter::format(m_drop_upper_treshold));
	g_log->information("autodrop.treshold.lower: " + NumberFormatter::format(m_drop_lower_treshold));
	g_log->information("ui.customname: " + m_host_custom_name);
	g_log->information("ui.tags: " + m_host_tags);
	g_log->information("ui.custommap: " + m_host_custom_map);
	g_log->information("ui.is_hidden: " + m_host_hidden);
	g_log->information("ui.hidden_processes: " + m_hidden_processes);
	g_log->information("autoupdate.enabled: " + bool_as_text(m_autoupdate_enabled));
	g_log->information("protobuf.print: " + bool_as_text(m_print_protobuf));
	g_log->information("watchdog.enabled: " + bool_as_text(m_watchdog_enabled));
	g_log->information("watchdog.sinsp_worker.timeout_s: " + NumberFormatter::format(m_watchdog_sinsp_worker_timeout_s));
	g_log->information("watchdog.connection_manager.timeout_s: " + NumberFormatter::format(m_watchdog_connection_manager_timeout_s));
	g_log->information("watchdog.analyzer.tid_collision.check_interval_s: " + NumberFormatter::format(m_watchdog_analyzer_tid_collision_check_interval_s));
	g_log->information("watchdog.sinsp_data_handler.timeout_s: " + NumberFormatter::format(m_watchdog_sinsp_data_handler_timeout_s));
	g_log->information("watchdog.max.memory_usage_mb: " + NumberFormatter::format(m_watchdog_max_memory_usage_mb));
	g_log->information("dirty_shutdown.report.log_size_b: " + NumberFormatter::format(m_dirty_shutdown_report_log_size_b));
	g_log->information("capture.dragent.events: " + bool_as_text(m_capture_dragent_events));
	g_log->information("protocols.enabled: " + bool_as_text(m_protocols_enabled));
	g_log->information("remotefs.enabled: " + bool_as_text(m_remotefs_enabled));

	if(m_aws_metadata.m_valid)
	{
		g_log->information("AWS public-ipv4: " + NumberFormatter::format(m_aws_metadata.m_public_ipv4));
		g_log->information("AWS instance-id: " + m_aws_metadata.m_instance_id);
	}

	g_log->information("jmx.sampling: " + NumberFormatter::format(m_jmx_sampling));

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
