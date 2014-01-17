#include "configuration.h"

#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/StreamCopier.h"

#include "logger.h"

using namespace Poco;
using namespace Poco::Net;

volatile bool dragent_configuration::m_signal_dump = false;
volatile bool dragent_configuration::m_terminate = false;

dragent_configuration::dragent_configuration()
{
	m_daemon = false;
	m_server_port = 0;
	m_transmitbuffer_size = 0;
	m_ssl_enabled = false;
	m_compression_enabled = false;
	m_emit_full_connections = false;
	m_min_file_priority = (Message::Priority) 0;
	m_min_console_priority = (Message::Priority) 0;
	m_evtcnt = 0;
	m_subsampling_ratio = 1;
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
	LayeredConfiguration& config = app->config();

	Path configuration_file = Poco::Path::forDirectory(config.getString("application.dir"));

	configuration_file.setFileName("dragent.properties");

	try
	{
		app->loadConfiguration(configuration_file.toString()); 
	}
	catch(...)
	{

	}

	m_daemon = config.getBool("application.runAsDaemon", false);

	if(m_daemon)
	{
		m_root_dir = "/opt/draios";
	}
	else
	{
		m_root_dir = Path::current();
	}

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
		m_server_addr = config.getString("server.address", "collector.draios.com");
	}

	if(m_server_port == 0)
	{
		m_server_port = config.getInt("server.port", 6666);
	}

	if(m_min_file_priority == 0)
	{
#ifdef _DEBUG
		m_min_file_priority = string_to_priority(config.getString("logpriority.file", "debug"));
#else
//		m_min_file_priority = string_to_priority(config.getString("logpriority.file", "info"));
		m_min_file_priority = string_to_priority(config.getString("logpriority.file", "debug"));
#endif		
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
}

void dragent_configuration::print_configuration()
{
	g_log->information("rootdir: " + m_root_dir);
	g_log->information("metricsfile.location: " + m_metrics_dir);
	g_log->information("logfile.location: " + m_log_dir);
	g_log->information("customerid: " + m_customer_id);
	g_log->information("server.address: " + m_server_addr);
	g_log->information("server.port: " + NumberFormatter::format(m_server_port));
	g_log->information("logpriority.file: " + NumberFormatter::format(m_min_file_priority));
	g_log->information("logpriority.console: " + NumberFormatter::format(m_min_console_priority));
	g_log->information("transmitbuffer.size: " + NumberFormatter::format(m_transmitbuffer_size));
	g_log->information("ssl.enabled: " + (m_ssl_enabled ? string("true") : string("false")));	
	g_log->information("ssl.ca_certificate: " + m_ssl_ca_certificate);
	g_log->information("compression.enabled: " + (m_compression_enabled ? string("true") : string("false")));
	g_log->information("emitfullconnections.enabled: " + (m_emit_full_connections ? string("true") : string("false")));
	g_log->information("dumpdir: " + m_dump_dir);
	g_log->information("subsampling.ratio: " + NumberFormatter::format(m_subsampling_ratio));
}

bool dragent_configuration::get_aws_metadata(aws_metadata* metadata)
{
	try 
	{
		HTTPClientSession client("169.254.169.254", 80);
		client.setTimeout(1000000);

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
			g_log->information("Received invalid AWS public-ipv4: '" + s + "'");
			return false;
		}

		metadata->m_public_ipv4 = addr.s_addr;
#endif

		g_log->information("AWS public-ipv4: " + s);

		return true;
	}
	catch(Poco::Exception& e)
	{
		g_log->information("Cannot get AWS metadata: " + e.displayText());
		return false;
	}
}

uint64_t dragent_configuration::get_current_time_ns()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return tv.tv_sec * (uint64_t) 1000000000 + tv.tv_usec * 1000;
}
