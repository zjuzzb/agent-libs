#include "configuration.h"

#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/StreamCopier.h"
#include "Poco/File.h"
#include <netdb.h>

#include "logger.h"
#include "uri.h"

#include <sys/time.h>
#include <sys/resource.h>

using namespace Poco;
using namespace Poco::Net;

volatile bool dragent_configuration::m_signal_dump = false;
volatile bool dragent_configuration::m_terminate = false;
volatile bool dragent_configuration::m_send_log_report = false;

static std::string bool_as_text(bool b)
{
	return b ? "true" : "false";
}

dragent_configuration::dragent_configuration()
{
	m_server_port = 0;
	m_transmitbuffer_size = 0;
	m_ssl_enabled = false;
	m_ssl_verify_certificate = true;
	m_compression_enabled = false;
	m_emit_full_connections = false;
	m_min_file_priority = (Message::Priority) -1;
	m_min_console_priority = (Message::Priority) -1;
	m_min_event_priority = (Message::Priority) -1;
	m_evtcnt = 0;
	m_subsampling_ratio = 1;
	m_autodrop_enabled = false;
	m_falco_baselining_enabled = true;
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
	m_protocols_truncation_size = 0;
	m_remotefs_enabled = false;
	m_agent_installed = true;
	m_ssh_enabled = true;
	m_statsd_enabled = true;
	m_statsd_limit = 100;
	m_sdjagent_enabled = true;
	m_app_checks_enabled = true;
	m_enable_coredump = false;
}

Message::Priority dragent_configuration::string_to_priority(const string& priostr)
{
	if(strncasecmp(priostr.c_str(), "emergency", 9) == 0)
	{
		return (Message::Priority)0;
	}
	else if(strncasecmp(priostr.c_str(), "alert", 5) == 0 ||
			strncasecmp(priostr.c_str(), "fatal", 5) == 0)
	{
		return Message::PRIO_FATAL;
	}
	else if(strncasecmp(priostr.c_str(), "critical", 8) == 0)
	{
		return Message::PRIO_CRITICAL;
	}
	else if(strncasecmp(priostr.c_str(), "error", 5) == 0)
	{
		return Message::PRIO_ERROR;
	}
	else if(strncasecmp(priostr.c_str(), "warn", 4) == 0)
	{
		return Message::PRIO_WARNING;
	}
	else if(strncasecmp(priostr.c_str(), "notice", 6) == 0)
	{
		return Message::PRIO_NOTICE;
	}
	else if(strncasecmp(priostr.c_str(), "info", 4) == 0)
	{
		return Message::PRIO_INFORMATION;
	}
	else if(strncasecmp(priostr.c_str(), "debug", 5) == 0)
	{
		return Message::PRIO_DEBUG;
	}
	else if(strncasecmp(priostr.c_str(), "trace", 5) == 0)
	{
		return Message::PRIO_TRACE;
	}
	else if(priostr.empty() || strncasecmp(priostr.c_str(), "none", 4) == 0)
	{
		return (Message::Priority)-1;
	}
	else
	{
		throw sinsp_exception("Invalid log priority. Accepted values are: 'none', 'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug', 'trace'.");
	}
}

void dragent_configuration::normalize_path(const std::string& file_path, std::string& normalized_path)
{
	normalized_path.clear();
	if(file_path.size())
	{
		if(file_path[0] == '/')
		{
			normalized_path = file_path;
		}
		else
		{
			Path path(file_path);
			path.makeAbsolute(m_root_dir);
			normalized_path = path.toString();
		}
	}
}

void dragent_configuration::add_event_filter(user_event_filter_t::ptr_t& flt, const std::string& system, const std::string& component)
{
	if(!m_config) { return; }

	typedef std::set<string, ci_compare> seq_t;

	// shortcut to enable or disable all in dragent.yaml (overriding default)
	seq_t user_events = yaml_configuration::get_deep_sequence<seq_t>(*m_config, m_config->get_root(), "events", system);
	if(user_events.size())
	{
		if(user_events.find("all") != user_events.end())
		{
			if(!flt)
			{
				flt = std::make_shared<user_event_filter_t>();
			}
			flt->add(user_event_meta_t({ "all", { "all" } }));
			return;
		}
		else if(user_events.find("none") != user_events.end())
		{
			return;
		}
	}

	user_events = yaml_configuration::get_deep_sequence<seq_t>(*m_config, m_config->get_root(), "events", system, component);
	if(user_events.empty()) // nothing in dragent.yaml, fail over to dragent.default.yaml
	{
		user_events = yaml_configuration::get_deep_sequence<seq_t>(*m_config, *m_config->get_default_root(), "events", system, component);
	}
	if(user_events.size())
	{
		if(user_events.find("none") == user_events.end())
		{
			if(!flt)
			{
				flt = std::make_shared<user_event_filter_t>();
			}
			if(user_events.find("all") != user_events.end())
			{
				flt->add(user_event_meta_t(component, { "all" }));
				return;
			}
			flt->add(user_event_meta_t(component, user_events));
		}
	}
}

void dragent_configuration::configure_k8s_from_env()
{
	static const string k8s_ca_crt = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
	static const string k8s_bearer_token_file_name = "/var/run/secrets/kubernetes.io/serviceaccount/token";
	if(m_k8s_api_server.empty())
	{
		// K8s API server not set by user, try to auto-discover.
		// This will work only when agent runs in a K8s pod.
		char* sh = getenv("KUBERNETES_SERVICE_HOST");
		if(sh && strlen(sh))
		{
			char* sp = getenv("KUBERNETES_SERVICE_PORT_HTTPS");
			if(sp && strlen(sp)) // secure
			{
				m_k8s_api_server = "https://";
				m_k8s_api_server.append(sh).append(1, ':').append(sp);
				if(m_k8s_bt_auth_token.empty())
				{
					if(File(k8s_bearer_token_file_name).exists())
					{
						m_k8s_bt_auth_token = k8s_bearer_token_file_name;
					}
					else
					{
						g_logger.log("Berarer token not found at default location (" + k8s_bearer_token_file_name +
									 "), authentication may not work. "
									 "If needed, please specify the location using k8s_bt_auth_token config entry.",
									 sinsp_logger::SEV_WARNING);
					}
				}
				if(m_k8s_ssl_verify_certificate && m_k8s_ssl_ca_certificate.empty())
				{
					if(File(k8s_ca_crt).exists())
					{
						m_k8s_ssl_ca_certificate = k8s_ca_crt;
					}
					else
					{
						g_logger.log("CA certificate verification configured, but CA certificate "
									 "not specified nor found at default location (" + k8s_ca_crt +
									 "), server authentication will not work. If server authentication "
									 "is desired, please specify the CA certificate file location using "
									 "k8s_ca_certificate config entry.",
									 sinsp_logger::SEV_WARNING);
					}
				}
			}
			else
			{
				sp = getenv("KUBERNETES_SERVICE_PORT");
				if(sp && strlen(sp))
				{
					m_k8s_api_server = "http://";
					m_k8s_api_server.append(sh).append(1, ':').append(sp);
				}
			}
		}
	}
}

void dragent_configuration::init(Application* app)
{
	refresh_machine_id();

	File package_dir("/opt/draios");
	if(package_dir.exists())
	{
		m_agent_installed = true;
		m_root_dir = "/opt/draios";
		m_conf_file = Path(m_root_dir).append("etc").append("dragent.yaml").toString();
		m_defaults_conf_file = Path(m_root_dir).append("etc").append("dragent.default.yaml").toString();
	}
	else
	{
		m_agent_installed = false;
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

	m_machine_id_prefix = m_config->get_scalar<string>("machine_id_prefix", "");

	if(m_min_file_priority == -1)
	{
#ifdef _DEBUG
		m_min_file_priority = string_to_priority(m_config->get_scalar<string>("log", "file_priority", "debug"));
#else
		m_min_file_priority = string_to_priority(m_config->get_scalar<string>("log", "file_priority", "info"));
#endif
	}

	if(m_min_console_priority == -1)
	{
#ifdef _DEBUG
		m_min_console_priority = string_to_priority(m_config->get_scalar<string>("log", "console_priority", "debug"));
#else
		m_min_console_priority = string_to_priority(m_config->get_scalar<string>("log", "console_priority", "info"));
#endif
	}

	if(m_min_event_priority == -1)
	{
#ifdef _DEBUG
		m_min_event_priority = string_to_priority(m_config->get_scalar<string>("log", "event_priority", "debug"));
#else
		m_min_event_priority = string_to_priority(m_config->get_scalar<string>("log", "event_priority", "info"));
#endif
	}

	//
	// user-configured events
	//

	if(m_min_event_priority != -1)
	{
		// kubernetes
		add_event_filter(m_k8s_event_filter, "kubernetes", "node");
		add_event_filter(m_k8s_event_filter, "kubernetes", "pod");
		add_event_filter(m_k8s_event_filter, "kubernetes", "replicationController");

		// docker
		add_event_filter(m_docker_event_filter, "docker", "container");
		add_event_filter(m_docker_event_filter, "docker", "image");
		add_event_filter(m_docker_event_filter, "docker", "volume");
		add_event_filter(m_docker_event_filter, "docker", "network");
	}

	m_curl_debug = m_config->get_scalar<bool>("curl_debug", false);

	m_transmitbuffer_size = m_config->get_scalar<uint32_t>("transmitbuffer_size", DEFAULT_DATA_SOCKET_BUF_SIZE);
	m_ssl_enabled = m_config->get_scalar<bool>("ssl", true);
	m_ssl_verify_certificate = m_config->get_scalar<bool>("ssl_verify_certificate", true);
	m_ssl_ca_certificate = Path(m_root_dir).append(m_config->get_scalar<string>("ca_certificate", "root.cert")).toString();
	m_compression_enabled = m_config->get_scalar<bool>("compression", "enabled", true);
	m_emit_full_connections = m_config->get_scalar<bool>("emitfullconnections_enabled", false);
	m_dump_dir = m_config->get_scalar<string>("dumpdir", "/tmp/");
	m_subsampling_ratio = m_config->get_scalar<decltype(m_subsampling_ratio)>("subsampling", "ratio", 1);
	m_autodrop_enabled =  m_config->get_scalar<bool>("autodrop", "enabled", true);
	m_falco_baselining_enabled =  m_config->get_scalar<bool>("falcobaseline", "enabled", true);
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
	m_watchdog_subprocesses_logger_timeout_s = m_config->get_scalar<decltype(m_watchdog_subprocesses_logger_timeout_s)>("watchdog", "subprocesses_logger_timeout_s", 60);
	m_watchdog_analyzer_tid_collision_check_interval_s = m_config->get_scalar<decltype(m_watchdog_analyzer_tid_collision_check_interval_s)>("watchdog", "analyzer_tid_collision_check_interval_s", 600);
	m_watchdog_sinsp_data_handler_timeout_s = m_config->get_scalar<decltype(m_watchdog_sinsp_data_handler_timeout_s)>("watchdog", "sinsp_data_handler_timeout_s", 60);
	m_watchdog_max_memory_usage_mb = m_config->get_scalar<decltype(m_watchdog_max_memory_usage_mb)>("watchdog", "max_memory_usage_mb", 512);
	// Right now these two entries does not support merging between defaults and specified on config file
	m_watchdog_max_memory_usage_subprocesses_mb = m_config->get_scalar<map<string, uint64_t>>("watchdog", "max_memory_usage_subprocesses", {{"sdchecks", 128U }, {"sdjagent", 256U}, {"mountedfs_reader", 32U}});
	m_watchdog_subprocesses_timeout_s = m_config->get_scalar<map<string, uint64_t>>("watchdog", "subprocesses_timeout_s", {{"sdchecks", 60U }, {"sdjagent", 60U}, {"mountedfs_reader", 60U}});

	m_dirty_shutdown_report_log_size_b = m_config->get_scalar<decltype(m_dirty_shutdown_report_log_size_b)>("dirty_shutdown", "report_log_size_b", 30 * 1024);
	m_capture_dragent_events = m_config->get_scalar<bool>("capture_dragent_events", false);
	m_jmx_sampling = m_config->get_scalar<decltype(m_jmx_sampling)>("jmx", "sampling", 1);
	m_protocols_enabled = m_config->get_scalar<bool>("protocols", true);
	m_protocols_truncation_size = m_config->get_scalar<uint32_t>("protocols_truncation_size", 512);
	m_remotefs_enabled = m_config->get_scalar<bool>("remotefs", false);
	auto java_home = m_config->get_scalar<string>("java_home", "");
	for(const auto& bin_path : { string("/usr/bin/java"), java_home + "/jre/bin/java", java_home + "/bin/java"})
	{
		File java_bin(bin_path);
		if(java_bin.exists() && java_bin.canExecute())
		{
			m_java_binary = bin_path;
		}
	}
	m_sdjagent_opts = m_config->get_scalar<string>("sdjagent_opts", "-Xmx256m");
	m_ssh_enabled = m_config->get_scalar<bool>("ssh_enabled", true);
	m_statsd_enabled = m_config->get_scalar<bool>("statsd", "enabled", true);
	m_statsd_limit = m_config->get_scalar<unsigned>("statsd", "limit", 100);
	m_sdjagent_enabled = m_config->get_scalar<bool>("jmx", "enabled", true);
	m_app_checks = m_config->get_merged_sequence<app_check>("app_checks");
	// Filter out disabled checks
	unordered_set<string> disabled_checks;
	for(const auto& item : m_app_checks)
	{
		if(!item.enabled())
		{
			disabled_checks.emplace(item.name());
		}
	}
	m_app_checks.erase(remove_if(m_app_checks.begin(), m_app_checks.end(), [&disabled_checks](const app_check& item)
	{
		return disabled_checks.find(item.name()) != disabled_checks.end();
	}), m_app_checks.end());
	vector<string> default_pythons = { "/usr/bin/python2.7", "/usr/bin/python27", "/usr/bin/python2",
										"/usr/bin/python2.6", "/usr/bin/python26"};
	auto python_binary_path = m_config->get_scalar<string>("python_binary", "");
	if(!python_binary_path.empty() && is_executable(python_binary_path))
	{
		m_python_binary = python_binary_path;
	}
	else
	{
		for(const auto& python : default_pythons)
		{
			if (is_executable(python))
			{
				m_python_binary = python;
				break;
			}
		}
	}

	m_app_checks_enabled = m_config->get_scalar<bool>("app_checks_enabled", true);
	m_containers_limit = m_config->get_scalar<uint32_t>("containers", "limit", 200);
	m_container_patterns = m_config->get_scalar<vector<string>>("containers", "include", {});
	auto known_server_ports = m_config->get_merged_sequence<uint16_t>("known_ports");
	for(auto p : known_server_ports)
	{
		m_known_server_ports.set(p);
	}
	m_blacklisted_ports = m_config->get_merged_sequence<uint16_t>("blacklisted_ports");

	for(auto ch : m_config->get_root()["chisels"])
	{
		sinsp_chisel_details details;

		try
		{
			details.m_name = ch["name"].as<string>();

			for(auto arg : ch["args"])
			{
				details.m_args.push_back(pair<string, string>(arg.first.as<string>().c_str(), arg.second.as<string>().c_str()));
			}

			m_chisel_details.push_back(details);
		}
		catch (const YAML::BadConversion& ex)
		{
			throw sinsp_exception("config file error at key: chisels");
		}
	}

	// K8s
	m_k8s_api_server = m_config->get_scalar<string>("k8s_uri", "");
	m_k8s_autodetect = m_config->get_scalar<bool>("k8s_autodetect", true);
	m_k8s_ssl_cert_type = m_config->get_scalar<string>("k8s_ssl_cert_type", "PEM");
	normalize_path(m_config->get_scalar<string>("k8s_ssl_cert", ""), m_k8s_ssl_cert);
	normalize_path(m_config->get_scalar<string>("k8s_ssl_key", ""), m_k8s_ssl_key);
	m_k8s_ssl_key_password = m_config->get_scalar<string>("k8s_ssl_key_password", "");
	normalize_path(m_config->get_scalar<string>("k8s_ca_certificate", ""), m_k8s_ssl_ca_certificate);
	m_k8s_ssl_verify_certificate = m_config->get_scalar<bool>("k8s_ssl_verify_certificate", false);
	m_k8s_timeout_ms = m_config->get_scalar<int>("k8s_timeout_ms", 10000);
	normalize_path(m_config->get_scalar<string>("k8s_bt_auth_token", ""), m_k8s_bt_auth_token);

	//////////////////////////////////////////////////////////////////////////////////////////
	// Logic for K8s metadata collection and agent auto-delegation, when K8s API server is 
	// - discovered automatically because (process is running on localhost):
	//     collection enabled and delegation disabled (handled in analyzer)
	// - discovered automatically via environment variables (agent running in a K8s pod):
	//     collection enabled and delegation enabled (default 2 delegated nodes, can be
	//     changed with k8s_delegated_nodes setting)
	// - configured statically:
	//     collection enabled and delegation disabled, unless delegation is manually enabled
	//     with k8s_delegated_nodes > 0
	//////////////////////////////////////////////////////////////////////////////////////////
	bool k8s_api_server_empty = m_k8s_api_server.empty();
	if(k8s_api_server_empty && m_k8s_autodetect)
	{ 
		configure_k8s_from_env();
	}
	if(k8s_api_server_empty && !m_k8s_api_server.empty()) // auto-discovered from env
	{
		m_k8s_delegated_nodes = m_config->get_scalar<int>("k8s_delegated_nodes", 2);
	}
	else if(!k8s_api_server_empty && !uri(m_k8s_api_server).is_local()) // configured but not localhost
	{
		m_k8s_delegated_nodes = m_config->get_scalar<int>("k8s_delegated_nodes", 0);
	}

	m_k8s_extensions = yaml_configuration::get_deep_sequence<k8s_ext_list_t>(*m_config, m_config->get_root(), "k8s_extensions");
	// End K8s

	// Mesos
	m_mesos_state_uri = m_config->get_scalar<string>("mesos_state_uri", "");
	auto marathon_uris = m_config->get_merged_sequence<string>("marathon_uris");
	for(auto u : marathon_uris)
	{
		m_marathon_uris.push_back(u);
	}
	m_mesos_autodetect = m_config->get_scalar<bool>("mesos_autodetect", true);
	m_mesos_timeout_ms = m_config->get_scalar<int>("mesos_timeout_ms", 10000);
	m_mesos_follow_leader = m_config->get_scalar<bool>("mesos_follow_leader",
							m_mesos_state_uri.empty() && m_mesos_autodetect ? true : false);
	// End Mesos

	m_enable_coredump = m_config->get_scalar<bool>("coredump", false);

	// Check existence of namespace to see if kernel supports containers
	File nsfile("/proc/self/ns/mnt");
	m_system_supports_containers = nsfile.exists();

	if(m_statsd_enabled)
	{
		write_statsite_configuration();
	}
	parse_services_file();
}

void dragent_configuration::print_configuration()
{
	for(const auto& item : m_config->errors())
	{
		g_log->critical(item);
	}
	g_log->information("Distribution: " + get_distribution());
	g_log->information("machine id: " + m_machine_id_prefix + m_machine_id);
	g_log->information("rootdir: " + m_root_dir);
	g_log->information("conffile: " + m_conf_file);
	g_log->information("metricsfile.location: " + m_metrics_dir);
	g_log->information("log.location: " + m_log_dir);
	g_log->information("customerid: " + m_customer_id);
	g_log->information("collector: " + m_server_addr);
	g_log->information("collector_port: " + NumberFormatter::format(m_server_port));
	g_log->information("log.file_priority: " + NumberFormatter::format(m_min_file_priority));
	g_log->information("log.console_priority: " + NumberFormatter::format(m_min_console_priority));
	g_log->information("log.event_priority: " + NumberFormatter::format(m_min_event_priority));
	g_log->information("CURL debug: " + bool_as_text(m_curl_debug));
	g_log->information("transmitbuffer_size: " + NumberFormatter::format(m_transmitbuffer_size));
	g_log->information("ssl: " + bool_as_text(m_ssl_enabled));
	g_log->information("ssl_verify_certificate: " + bool_as_text(m_ssl_verify_certificate));
	g_log->information("ca_certificate: " + m_ssl_ca_certificate);
	g_log->information("compression.enabled: " + bool_as_text(m_compression_enabled));
	g_log->information("emitfullconnections.enabled: " + bool_as_text(m_emit_full_connections));
	g_log->information("dumpdir: " + m_dump_dir);
	g_log->information("subsampling.ratio: " + NumberFormatter::format(m_subsampling_ratio));
	g_log->information("autodrop.enabled: " + bool_as_text(m_autodrop_enabled));
	g_log->information("falcobaseline.enabled: " + bool_as_text(m_falco_baselining_enabled));
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
	g_log->information("watchdog.subprocesses_logger_timeout_s: " + NumberFormatter::format(m_watchdog_subprocesses_logger_timeout_s));
	g_log->information("watchdog.analyzer_tid_collision_check_interval_s: " + NumberFormatter::format(m_watchdog_analyzer_tid_collision_check_interval_s));
	g_log->information("watchdog.sinsp_data_handler_timeout_s: " + NumberFormatter::format(m_watchdog_sinsp_data_handler_timeout_s));
	g_log->information("watchdog.max.memory_usage_mb: " + NumberFormatter::format(m_watchdog_max_memory_usage_mb));
	g_log->information("dirty_shutdown.report_log_size_b: " + NumberFormatter::format(m_dirty_shutdown_report_log_size_b));
	g_log->information("capture_dragent_events: " + bool_as_text(m_capture_dragent_events));
	g_log->information("protocols: " + bool_as_text(m_protocols_enabled));
	g_log->information("protocols_truncation_size: " + NumberFormatter::format(m_protocols_truncation_size));
	g_log->information("remotefs: " + bool_as_text(m_remotefs_enabled));
	g_log->information("jmx.sampling: " + NumberFormatter::format(m_jmx_sampling));
	g_log->information("java detected: " + bool_as_text(java_present()));
	g_log->information("java_binary: " + m_java_binary);
	g_log->information("sdjagent_opts:" + m_sdjagent_opts);
	g_log->information("ssh.enabled: " + bool_as_text(m_ssh_enabled));
	g_log->information("statsd enabled: " + bool_as_text(m_statsd_enabled));
	g_log->information("app_checks enabled: " + bool_as_text(m_app_checks_enabled));
	g_log->information("python binary: " + m_python_binary);
	g_log->information("known_ports: " + NumberFormatter::format(m_known_server_ports.count()));
	g_log->information("Kernel supports containers: " + bool_as_text(m_system_supports_containers));
	g_log->information("K8S autodetect enabled: " + bool_as_text(m_k8s_autodetect));
	g_log->information("K8S connection timeout [ms]: " + std::to_string(m_k8s_timeout_ms));
	if (!m_k8s_api_server.empty())
	{
		g_log->information("K8S API server: " + m_k8s_api_server);
		if(m_k8s_delegated_nodes && uri(m_k8s_api_server).is_local())
		{
			m_k8s_delegated_nodes = 0;
			g_logger.log("K8s API server is local, k8s_delegated_nodes (" +
						 std::to_string(m_k8s_delegated_nodes) + ") ignored.", sinsp_logger::SEV_WARNING);
		}
	}
	if(m_k8s_delegated_nodes)
	{
		g_log->information("K8S delegated nodes: " + std::to_string(m_k8s_delegated_nodes));
	}
	if (!m_k8s_ssl_cert_type.empty())
	{
		g_log->information("K8S certificate type: " + m_k8s_ssl_cert_type);
	}
	if (!m_k8s_ssl_cert.empty())
	{
		g_log->information("K8S certificate: " + m_k8s_ssl_cert);
	}
	if (!m_k8s_ssl_key.empty())
	{
		g_log->information("K8S SSL key: " + m_k8s_ssl_key);
	}
	if (!m_k8s_ssl_key_password.empty())
	{
		g_log->information("K8S key password specified.");
	}
	else
	{
		g_log->information("K8S key password not specified.");
	}
	if (!m_k8s_ssl_ca_certificate.empty())
	{
		g_log->information("K8S CA certificate: " + m_k8s_ssl_ca_certificate);
	}
	g_log->information("K8S certificate verification enabled: " + bool_as_text(m_k8s_ssl_verify_certificate));
	if (!m_k8s_bt_auth_token.empty())
	{
		g_log->information("K8S bearer token authorization: " + m_k8s_bt_auth_token);
	}
	if(!m_k8s_extensions.empty())
	{
		std::ostringstream os;
		os << std::endl;
		for(const auto& ext : m_k8s_extensions)
		{
			os << ext << std::endl;
		}
		g_log->information("K8S extensions:" + os.str());
	}
	if(!m_blacklisted_ports.empty())
	{
		g_log->information("blacklisted_ports count: " + NumberFormatter::format(m_blacklisted_ports.size()));
	}
	if(!m_aws_metadata.m_instance_id.empty())
	{
		g_log->information("AWS instance-id: " + m_aws_metadata.m_instance_id);
	}
	if(m_aws_metadata.m_public_ipv4)
	{
		g_log->information("AWS public-ipv4: " + NumberFormatter::format(m_aws_metadata.m_public_ipv4));
	}
	if(!m_mesos_state_uri.empty())
	{
		g_log->information("Mesos state API server: " + m_mesos_state_uri);
	}
	if(!m_marathon_uris.empty())
	{
		for(const auto& marathon_uri : m_marathon_uris)
		{
			g_log->information("Marathon groups API server: " + marathon_uri);
			g_log->information("Marathon apps API server: " + marathon_uri);
		}
	}
	else
	{
		g_log->information("Marathon API server not configured.");
	}
	g_log->information("Mesos autodetect enabled: " + bool_as_text(m_mesos_autodetect));
	g_log->information("Mesos connection timeout [ms]: " + std::to_string(m_mesos_timeout_ms));
	g_log->information("Mesos leader following enabled: " + bool_as_text(m_mesos_follow_leader));
	g_log->information("coredump enabled: " + bool_as_text(m_enable_coredump));

	if(m_k8s_event_filter)
	{
		g_log->information("K8s events filter:" + m_k8s_event_filter->to_string());
	}
	else
	{
		g_log->information("K8s events not enabled.");
	}
	if(m_docker_event_filter)
	{
		g_log->information("Docker events filter:" + m_docker_event_filter->to_string());
	}
	else
	{
		g_log->information("Docker events not enabled.");
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
				m_aws_metadata.m_public_ipv4 = 0;
			}
			else
			{
				m_aws_metadata.m_public_ipv4 = addr.s_addr;
			}
#endif
		}

		{
			HTTPRequest request(HTTPRequest::HTTP_GET, "/latest/meta-data/instance-id");
			client.sendRequest(request);

			HTTPResponse response; 
			std::istream& rs = client.receiveResponse(response); 

			StreamCopier::copyToString(rs, m_aws_metadata.m_instance_id);
			if(m_aws_metadata.m_instance_id.find("i-") != 0)
			{
				m_aws_metadata.m_instance_id.clear();
			}
		}
	}
	catch(Poco::Exception& e)
	{
		m_aws_metadata.m_public_ipv4 = 0;
		m_aws_metadata.m_instance_id.clear();
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

void dragent_configuration::write_statsite_configuration()
{
	static const char STATSITE_INI_TEMPLATE[] =
			"# WARNING: File generated automatically, don't edit. Please use \"dragent.yaml\" instead\n"
					"[statsite]\n"
					"bind_address = 127.0.0.1\n"
					"port = %u\n"
					"udp_port = %u\n"
					"log_level = %s\n"
					"flush_interval = %u\n"
					"parse_stdin = 1\n";

	auto tcp_port = m_config->get_scalar<uint16_t>("statsd", "tcp_port", 8125);
	auto udp_port = m_config->get_scalar<uint16_t>("statsd", "udp_port", 8125);
	auto flush_interval = m_config->get_scalar<uint16_t>("statsd", "flush_interval", 1);

	// convert our loglevel to statsite one
	// our levels: debug, info, warning, error
	// statsite levels: DEBUG, INFO, WARN, ERROR, CRITICAL
	auto loglevel = m_config->get_scalar<string>("log", "file_priority", "info");
	static const unordered_map<string, string> conversion_map{ { "debug", "DEBUG" }, { "info", "INFO" },
															   {"warning", "WARN"}, {"error", "ERROR"}};
	if (conversion_map.find(loglevel) != conversion_map.end())
	{
		loglevel = conversion_map.at(loglevel);
	}
	else
	{
		loglevel = "INFO";
	}

	char formatted_config[sizeof(STATSITE_INI_TEMPLATE)+100];
	snprintf(formatted_config, sizeof(formatted_config), STATSITE_INI_TEMPLATE, tcp_port, udp_port, loglevel.c_str(), flush_interval);

	string filename("/opt/draios/etc/statsite.ini");
	if(!m_agent_installed)
	{
		filename = "statsite.ini";
	}
	std::ofstream ostr(filename);
	if(ostr.good())
	{
		ostr << formatted_config;
	}
	ostr.close();
}

void dragent_configuration::refresh_machine_id()
{
	m_machine_id = Environment::nodeId();
}

bool dragent_configuration::is_executable(const string &path)
{
	File file(path);
	return file.exists() && file.canExecute();
}

void dragent_configuration::parse_services_file()
{
	auto service = getservent();
	while(service != NULL)
	{
		m_known_server_ports.set(ntohs(service->s_port));
		service = getservent();
	}
	endservent();
}

bool YAML::convert<app_check>::decode(const YAML::Node &node, app_check &rhs)
{
	/*
	 * Example:
	 * name: redisdb
	 *	pattern:
	 *	  comm: redis-server
	 *	conf:
	 *	  host: 127.0.0.1
	 *	  port: {port}
	 *
	 *	The conf part is not used by dragent
	 */
	rhs.m_name = node["name"].as<string>();
	auto enabled_node = node["enabled"];
	if(enabled_node.IsScalar())
	{
		rhs.m_enabled = enabled_node.as<bool>();
	}

	auto pattern_node = node["pattern"];
	if(pattern_node.IsMap())
	{
		auto comm_node = pattern_node["comm"];
		if(comm_node.IsScalar())
		{
			rhs.m_comm_pattern = comm_node.as<string>();
		}
		auto exe_node = pattern_node["exe"];
		if(exe_node.IsScalar())
		{
			rhs.m_exe_pattern = exe_node.as<string>();
		}
		auto port_node = pattern_node["port"];
		if(port_node.IsScalar())
		{
			rhs.m_port_pattern = port_node.as<uint16_t>();
		}
		auto arg_node = pattern_node["arg"];
		if(arg_node.IsScalar())
		{
			rhs.m_arg_pattern = arg_node.as<string>();
		}
	}
	return true;
}