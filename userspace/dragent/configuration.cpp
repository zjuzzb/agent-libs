#include "configuration.h"

dragent_configuration::dragent_configuration()
{
	m_daemon = false;
	m_server_port = 0;
	m_transmitbuffer_size = 0;
	m_dropping_mode = false;
	m_ssl_enabled = false;
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
	m_customer_id = config.getString("customerid", "");
	m_server_addr = config.getString("server.address", "");
	m_server_port = config.getInt("server.port", 0);
	m_transmitbuffer_size = config.getInt("transmitbuffer.size", DEFAULT_DATA_SOCKET_BUF_SIZE);
	m_dropping_mode = config.getBool("droppingmode.enabled", false);
	m_ssl_enabled = config.getBool("ssl.enabled", false);
	m_ssl_ca_certificate = Path(m_root_dir).append(config.getString("ssl.ca_certificate", "")).toString();
	m_compression_enabled = config.getBool("compression.enabled", true);
}

void dragent_configuration::print_configuration()
{
	g_log->information("rootdir: " + m_root_dir);
	g_log->information("metricsfile.location: " + m_metrics_dir);
	g_log->information("logfile.location: " + m_log_dir);
	g_log->information("customerid: " + m_customer_id);
	g_log->information("server.address: " + m_server_addr);
	g_log->information("server.port: " + NumberFormatter::format(m_server_port));
	g_log->information("transmitbuffer.size: " + NumberFormatter::format(m_transmitbuffer_size));
	g_log->information("droppingmode.enabled: " + (m_dropping_mode ? string("true") : string("false")));	
	g_log->information("ssl.enabled: " + (m_ssl_enabled ? string("true") : string("false")));	
	g_log->information("ssl.ca_certificate: " + m_ssl_ca_certificate);
	g_log->information("compression.enabled: " + m_compression_enabled);
}
