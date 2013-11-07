#include "configuration.h"

dragent_configuration::dragent_configuration()
{
	m_daemon = false;
	m_server_port = 0;
	m_transmitbuffer_size = 0;
	m_dropping_mode = false;
	m_ssl_enabled = false;
	m_compression_enabled = false;
	m_emit_full_connections = false;
}

Message::Priority dragent_configuration::string_to_priority(string priostr)
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
	m_metrics_dir = Path(m_root_dir).append(config.getString("metricsfile.location", "metrics")).toString();
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

	m_min_file_priority = string_to_priority(config.getString("logpriority.file", "debug"));
	m_min_console_priority = string_to_priority(config.getString("logpriority.console", "debug"));
	m_transmitbuffer_size = config.getInt("transmitbuffer.size", DEFAULT_DATA_SOCKET_BUF_SIZE);
	m_dropping_mode = config.getBool("droppingmode.enabled", false);
	m_ssl_enabled = config.getBool("ssl.enabled", true);
	m_ssl_ca_certificate = Path(m_root_dir).append(config.getString("ssl.ca_certificate", "root.cert")).toString();
	m_compression_enabled = config.getBool("compression.enabled", true);
	m_emit_full_connections = config.getBool("emitfullconnections.enabled", false);
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
	g_log->information("droppingmode.enabled: " + (m_dropping_mode ? string("true") : string("false")));	
	g_log->information("ssl.enabled: " + (m_ssl_enabled ? string("true") : string("false")));	
	g_log->information("ssl.ca_certificate: " + m_ssl_ca_certificate);
	g_log->information("compression.enabled: " + (m_compression_enabled ? string("true") : string("false")));
	g_log->information("emitfullconnections.enabled: " + (m_emit_full_connections ? string("true") : string("false")));
}
