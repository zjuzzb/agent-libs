#include "configuration.h"

#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/StreamCopier.h"
#include "Poco/File.h"
#include <netdb.h>

#include "falco_engine.h"

#include "logger.h"
#include "uri.h"

#include <sys/time.h>
#include <sys/resource.h>

using namespace Poco;
using namespace Poco::Net;

volatile bool dragent_configuration::m_signal_dump = false;
volatile bool dragent_configuration::m_terminate = false;
volatile bool dragent_configuration::m_send_log_report = false;
volatile bool dragent_configuration::m_config_update = false;

static std::string bool_as_text(bool b)
{
	return b ? "true" : "false";
}

dragent_auto_configuration::dragent_auto_configuration(const string &config_filename,
						       const string &config_directory,
						       const string &config_header)
	: m_config_filename(config_filename),
	  m_config_directory(config_directory),
	  m_config_header(config_header)
{
	init_digest();
}

int dragent_auto_configuration::save(dragent_configuration &config,
				     const string& config_data,
				     string &errstr)
{
	g_log->debug(string("Received ") + m_config_filename + string(" with content: ") + config_data);
	m_sha1_engine.reset();
	if(!config_data.empty())
	{
		m_sha1_engine.update(m_config_header);
		m_sha1_engine.update(config_data);
	}
	auto new_digest = m_sha1_engine.digest();

	g_log->debug(string("New digest=") + DigestEngine::digestToHex(new_digest) + " old digest= " + DigestEngine::digestToHex(m_digest));

	if(new_digest != m_digest)
	{
		if(!validate(config_data, errstr))
		{
			return -1;
		}

		string path = config_path();

		if(config_data.empty())
		{
			File auto_config_f(path);
			auto_config_f.remove();
		}
		else
		{
			ofstream auto_config_f(path);
			auto_config_f << m_config_header << config_data;
			auto_config_f.close();
		}

		apply(config);
	}
	else
	{
		g_log->debug("Auto config file is already up-to-date");
		return 0;
	}

	m_digest = new_digest;

	return 1;
}

void dragent_auto_configuration::init_digest()
{
	string path = config_path();

	m_sha1_engine.reset();

	if(path.size() > 0)
	{
		// Save initial digest
		File auto_config_file(path);
		if(auto_config_file.exists())
		{
			ifstream auto_config_f(auto_config_file.path());
			char readbuf[4096];
			while(auto_config_f.good())
			{
				auto_config_f.read(readbuf, sizeof(readbuf));
				m_sha1_engine.update(readbuf, auto_config_f.gcount());
			}
		}
	}
	m_digest = m_sha1_engine.digest();
};

std::string dragent_auto_configuration::digest()
{
	return DigestEngine::digestToHex(m_digest);
}

const std::string dragent_auto_configuration::config_path()
{
	return Path(m_config_directory).append(m_config_filename).toString();
}

void dragent_auto_configuration::set_config_directory(const std::string &config_directory)
{
	m_config_directory = config_directory;
	init_digest();
}

class dragent_yaml_auto_configuration
	: public dragent_auto_configuration
{
public:
	dragent_yaml_auto_configuration(const std::string &config_directory)
		: dragent_auto_configuration("dragent.auto.yaml",
					     config_directory,
					     "#\n"
					     "# WARNING: Sysdig Cloud Agent auto configuration, don't edit. Please use \"dragent.yaml\" instead\n"
					     "#          To disable it, put \"auto_config: false\" on \"dragent.yaml\" and then delete this file.\n"
					     "#\n"),
		  m_forbidden_keys { "auto_config", "customerid", "collector", "collector_port",
			"ssl", "ssl_verify_certificate", "ca_certificate", "compression" }
	{
	};

	~dragent_yaml_auto_configuration()
	{
	};

	bool validate(const string &config_data, string &errstr)
	{
		yaml_configuration new_conf(config_data);
		if(!new_conf.errors().empty())
		{
			errstr = "New auto config is not valid, skipping it";
			return false;
		}
		for(const auto& key : m_forbidden_keys)
		{
			if(new_conf.get_scalar<string>(key, "default") != "default" || !new_conf.errors().empty()) {
				errstr = "Overriding key=" + key + " on autoconfig is forbidden";
				return false;
			}
		}

		return true;
	}

	void apply(dragent_configuration &config)
	{
		g_log->information("New agent auto config file applied");
		config.m_config_update = true;
		config.m_terminate = true;
	}

private:
	const vector<string> m_forbidden_keys;
};

class falco_rules_auto_configuration
	: public dragent_auto_configuration
{
public:
	falco_rules_auto_configuration(const std::string &config_directory)
		: dragent_auto_configuration("falco_rules.auto.yaml",
					     config_directory,
					     "#\n"
					     "# WARNING: Falco Engine auto configuration, don't edit. Please use \"falco_rules.yaml\" instead\n"
					     "#          To disable it, put \"auto_config: false\" on \"dragent.yaml\" and then delete this file.\n"
					     "#\n")
	{
	};

	~falco_rules_auto_configuration()
	{
	};

	bool validate(const string &config_data, string &errstr)
	{
		falco_engine eng;
		sinsp *inspector = new sinsp();
		bool verbose = false;
		bool all_events = false;

		eng.set_inspector(inspector);

		try {
			eng.load_rules(config_data, verbose, all_events);
		}
		catch (falco_exception &e)
		{
			errstr = string(e.what());
			delete(inspector);
			return false;
		}
		delete(inspector);
		return true;
	}

	void apply(dragent_configuration &config)
	{
		g_log->information("New auto falco rules file applied");
		config.m_reset_falco_engine = true;
	}
};


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
	m_watchdog_warn_memory_usage_mb = 0;
	m_watchdog_heap_profiling_interval_s = 0;
	m_dirty_shutdown_report_log_size_b = 0;
	m_capture_dragent_events = false;
	m_jmx_sampling = 1;
	m_protocols_enabled = true;
	m_protocols_truncation_size = 0;
	m_remotefs_enabled = false;
	m_agent_installed = true;
	m_ssh_enabled = true;
	m_sysdig_capture_enabled = true;
	m_statsd_enabled = true;
	m_statsd_limit = 100;
	m_statsd_port = 8125;
	m_sdjagent_enabled = true;
	m_jmx_limit = 500;
	m_app_checks_enabled = true;
	m_enable_coredump = false;
	m_auto_config = true;
	m_enable_falco_engine = false;
	m_falco_fallback_default_rules_filename = "/opt/draios/etc/falco_rules.default.yaml";
	m_falco_engine_sampling_multiplier = 0;
	m_reset_falco_engine = false;
	m_user_events_rate = 1;
	m_user_max_burst_events = 1000;
	m_load_error = false;
	m_mode = dragent_mode_t::STANDARD;
	m_app_checks_limit = 300;
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
	const auto& roots = m_config->get_roots();

	// shortcut to enable or disable all in dragent.yaml or dragent.auto.yaml (overriding default)
	seq_t user_events;
	for (const auto& root: roots)
	{
		user_events = yaml_configuration::get_deep_sequence<seq_t>(*m_config, root, "events", system);
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
	}

	// find the first `user_events` across our files
	for(const auto& root : roots)
	{
		user_events = yaml_configuration::get_deep_sequence<seq_t>(*m_config, root, "events", system, component);
		if(!user_events.empty())
		{
			break;
		}
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
						m_k8s_logs.insert({sinsp_logger::SEV_WARNING, "Bearer token not found at default location (" + k8s_bearer_token_file_name +
									 "), authentication may not work. "
									 "If needed, please specify the location using k8s_bt_auth_token config entry."});
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
						m_k8s_logs.insert({sinsp_logger::SEV_WARNING, "CA certificate verification configured, but CA certificate "
									 "not specified nor found at default location (" + k8s_ca_crt +
									 "), server authentication will not work. If server authentication "
									 "is desired, please specify the CA certificate file location using "
									 "k8s_ca_certificate config entry."});
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

	unique_ptr<dragent_auto_configuration> autocfg(new dragent_yaml_auto_configuration(Path(m_root_dir).append("etc").toString()));

	if(m_auto_config)
	{
		m_config.reset(new yaml_configuration({ m_conf_file, autocfg->config_path(), m_defaults_conf_file }));
	}
	else
	{
		m_config.reset(new yaml_configuration({ m_conf_file, m_defaults_conf_file }));
	}
	// The yaml_configuration catches exceptions so m_config will always be
	// a valid pointer, but set m_load_error so dragent will see the error
	if(!m_config->errors().empty())
	{
		m_load_error = true;
	}
	
	m_supported_auto_configs[string("dragent.auto.yaml")] = unique_ptr<dragent_auto_configuration>(std::move(autocfg));

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
		add_event_filter(m_k8s_event_filter, "kubernetes", "replicaSet");
		add_event_filter(m_k8s_event_filter, "kubernetes", "daemonSet");
		add_event_filter(m_k8s_event_filter, "kubernetes", "deployment");

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

	m_autodrop_enabled = m_config->get_scalar<bool>("autodrop", "enabled", true);
	m_falco_baselining_enabled =  m_config->get_scalar<bool>("falcobaseline", "enabled", false);

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
	m_watchdog_warn_memory_usage_mb = m_config->get_scalar<decltype(m_watchdog_warn_memory_usage_mb)>("watchdog", "warn_memory_usage_mb",
													  m_watchdog_max_memory_usage_mb / 2);
	if(m_watchdog_warn_memory_usage_mb > m_watchdog_max_memory_usage_mb)
	{
		m_config->add_warning("watchdog:warn_memory_usage_mb cannot be higher than watchdog:max_memory_usage_mb");
		m_watchdog_warn_memory_usage_mb = m_watchdog_max_memory_usage_mb;
	}
	m_watchdog_heap_profiling_interval_s = m_config->get_scalar<decltype(m_watchdog_heap_profiling_interval_s)>("watchdog", "heap_profiling_interval_s", 0);
	// Right now these two entries does not support merging between defaults and specified on config file
	m_watchdog_max_memory_usage_subprocesses_mb = m_config->get_scalar<map<string, uint64_t>>("watchdog", "max_memory_usage_subprocesses", {{"sdchecks", 128U }, {"sdjagent", 256U}, {"mountedfs_reader", 32U}, {"statsite_forwarder", 32U}});
	m_watchdog_subprocesses_timeout_s = m_config->get_scalar<map<string, uint64_t>>("watchdog", "subprocesses_timeout_s", {{"sdchecks", 60U }, {"sdjagent", 60U}, {"mountedfs_reader", 60U}, {"statsite_forwarder", 60U}});

	m_dirty_shutdown_report_log_size_b = m_config->get_scalar<decltype(m_dirty_shutdown_report_log_size_b)>("dirty_shutdown", "report_log_size_b", 30 * 1024);
	m_capture_dragent_events = m_config->get_scalar<bool>("capture_dragent_events", false);
	m_jmx_sampling = m_config->get_scalar<decltype(m_jmx_sampling)>("jmx", "sampling", 1);
	m_protocols_enabled = m_config->get_scalar<bool>("protocols", true);
	m_protocols_truncation_size = m_config->get_scalar<uint32_t>("protocols_truncation_size", 512);
	m_remotefs_enabled = m_config->get_scalar<bool>("remotefs", false);
	auto java_home = m_config->get_scalar<string>("java_home", "");
	for(const auto& bin_path : { string("/usr/bin/java"), java_home + "/jre/bin/java", java_home + "/bin/java"})
	{
		if(is_executable(bin_path))
		{
			m_java_binary = bin_path;
			break;
		}
	}
	m_sdjagent_opts = m_config->get_scalar<string>("sdjagent_opts", "-Xmx256m");
	m_ssh_enabled = m_config->get_scalar<bool>("ssh_enabled", true);
	m_sysdig_capture_enabled = m_config->get_scalar<bool>("sysdig_capture_enabled", true);
	m_statsd_enabled = m_config->get_scalar<bool>("statsd", "enabled", true);
	m_statsd_limit = m_config->get_scalar<unsigned>("statsd", "limit", 100);
	m_statsd_port = m_config->get_scalar<uint16_t>("statsd", "udp_port", 8125);
	m_sdjagent_enabled = m_config->get_scalar<bool>("jmx", "enabled", true);
	m_jmx_limit = m_config->get_scalar<unsigned>("jmx", "limit", 500);
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
	m_app_checks_limit = m_config->get_scalar<unsigned>("app_checks_limit", 300);

	m_containers_limit = m_config->get_scalar<uint32_t>("containers", "limit", 200);
	m_container_patterns = m_config->get_scalar<vector<string>>("containers", "include", {});
	auto known_server_ports = m_config->get_merged_sequence<uint16_t>("known_ports");
	for(auto p : known_server_ports)
	{
		m_known_server_ports.set(p);
	}
	m_blacklisted_ports = m_config->get_merged_sequence<uint16_t>("blacklisted_ports");

	for(const auto& root : m_config->get_roots())
	{
		const auto& node = root["chisels"];
		if(!node.IsSequence())
		{
			break;
		}
		for(auto ch : node)
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
	if(k8s_api_server_empty && m_k8s_api_server.empty())
	{
		m_k8s_delegated_nodes = 0;
	}
	if(k8s_api_server_empty && !m_k8s_api_server.empty()) // auto-discovered from env
	{
		m_k8s_delegated_nodes = m_config->get_scalar<int>("k8s_delegated_nodes", 2);
	}
	else if(!k8s_api_server_empty && !uri(m_k8s_api_server).is_local()) // configured but not localhost
	{
		m_k8s_delegated_nodes = m_config->get_scalar<int>("k8s_delegated_nodes", 0);
	}

	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// non-production private setting, only used for testing - to simulate delegation when     //
	// running [outside pod] AND [on the same host as K8s API server]                          //
	// it will work only if K8s API server is running on localhost                             //
	// this setting will NOT work when agent is running on another host and it should          //
	// *never* be set to true in production                                                    //
	m_k8s_simulate_delegation = m_config->get_scalar<bool>("k8s_simulate_delegation", false);  //
	if(m_k8s_simulate_delegation)                                                              //
	{                                                                                          //
		m_k8s_delegated_nodes = m_config->get_scalar<int>("k8s_delegated_nodes", 2);           //
		m_k8s_api_server = "http://127.0.0.1:8080";                                            //
	}                                                                                          //
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	if(m_k8s_delegated_nodes) // always force-disable autodiscovery if delegated
	{
		m_k8s_autodetect = false;
	}
	auto k8s_extensions_v = m_config->get_merged_sequence<k8s_ext_list_t::value_type>("k8s_extensions");
	m_k8s_extensions = k8s_ext_list_t(k8s_extensions_v.begin(), k8s_extensions_v.end());
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
	m_marathon_follow_leader = m_config->get_scalar<bool>("marathon_follow_leader",
							marathon_uris.empty() && m_mesos_autodetect ? true : false);
	m_mesos_credentials.first = m_config->get_scalar<std::string>("mesos_user", "");
	m_mesos_credentials.second = m_config->get_scalar<std::string>("mesos_password", "");
	m_marathon_credentials.first = m_config->get_scalar<std::string>("marathon_user", "");
	m_marathon_credentials.second = m_config->get_scalar<std::string>("marathon_password", "");
	m_dcos_enterprise_credentials.first = m_config->get_scalar<std::string>("dcos_user", "");
	m_dcos_enterprise_credentials.second = m_config->get_scalar<std::string>("dcos_password", "");

	// End Mesos

	m_enable_coredump = m_config->get_scalar<bool>("coredump", false);
	m_enable_falco_engine = m_config->get_scalar<bool>("falco_engine", "enabled", false);
	m_falco_default_rules_filename = m_config->get_scalar<string>("falco_engine", "default_rules_filename",
								      m_root_dir + "/etc/falco_rules.default.yaml");

	m_falco_auto_rules_filename = Path(m_root_dir).append("etc").append("falco_rules.auto.yaml").toString();

	m_supported_auto_configs[string("falco_rules.auto.yaml")] =
		unique_ptr<dragent_auto_configuration>(new falco_rules_auto_configuration(Path(m_root_dir).append("etc").toString()));

	m_falco_rules_filename = m_config->get_scalar<string>("falco_engine", "rules_filename",
							      m_root_dir + "/etc/falco_rules.yaml");

	m_falco_engine_disabled_rule_patterns = m_config->get_deep_merged_sequence<set<string>>("falco_engine", "disabled_rule_patterns");
	m_falco_engine_sampling_multiplier = m_config->get_scalar<double>("falco_engine", "sampling_multiplier", 0);

	m_user_events_rate = m_config->get_scalar<uint64_t>("events", "rate", 1);
	m_user_max_burst_events = m_config->get_scalar<uint64_t>("events", "max_burst", 1000);

	//
	// If falco is enabled, check to see if the rules file exists and
	// switch to a built-in default if it does not.
	//
	if(m_enable_falco_engine)
	{
		File rules_file(m_falco_default_rules_filename);
		if(!rules_file.exists())
		{
			m_falco_default_rules_filename = m_falco_fallback_default_rules_filename;
		}
	}

	// Check existence of namespace to see if kernel supports containers
	File nsfile("/proc/self/ns/mnt");
	m_system_supports_containers = nsfile.exists();

	if(m_statsd_enabled)
	{
		write_statsite_configuration();
	}
	parse_services_file();

	m_auto_config = m_config->get_scalar("auto_config", true);
	m_emit_tracers = m_config->get_scalar("debug_emit_tracers", false);

	auto mode_s = m_config->get_scalar<string>("run_mode", "standard");
	if(mode_s == "nodriver")
	{
		m_mode = dragent_mode_t::NODRIVER;
		// disabling features that don't work in this mode
		m_enable_falco_engine = false;
		m_falco_baselining_enabled = false;
		m_sysdig_capture_enabled = false;
		// our dropping mechanism can't help in this mode
		m_autodrop_enabled = false;
	}

	m_metrics_exclude = m_config->get_deep_merged_sequence<std::vector<std::string>>("metrics_filter", "exclude");
	m_metrics_include = m_config->get_deep_merged_sequence<std::vector<std::string>>("metrics_filter", "include");
}

void dragent_configuration::print_configuration()
{
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
	g_log->information("watchdog.max_memory_usage_mb: " + NumberFormatter::format(m_watchdog_max_memory_usage_mb));
	g_log->information("watchdog.warn_memory_usage_mb: " + NumberFormatter::format(m_watchdog_warn_memory_usage_mb));
	g_log->information("watchdog.heap_profiling_interval_s: " + NumberFormatter::format(m_watchdog_heap_profiling_interval_s));
	g_log->information("dirty_shutdown.report_log_size_b: " + NumberFormatter::format(m_dirty_shutdown_report_log_size_b));
	g_log->information("capture_dragent_events: " + bool_as_text(m_capture_dragent_events));
	g_log->information("User events rate: " + NumberFormatter::format(m_user_events_rate));
	g_log->information("User events max burst: " + NumberFormatter::format(m_user_max_burst_events));
	g_log->information("protocols: " + bool_as_text(m_protocols_enabled));
	g_log->information("protocols_truncation_size: " + NumberFormatter::format(m_protocols_truncation_size));
	g_log->information("remotefs: " + bool_as_text(m_remotefs_enabled));
	g_log->information("jmx.sampling: " + NumberFormatter::format(m_jmx_sampling));
	g_log->information("jmx.limit: " + NumberFormatter::format(m_jmx_limit));
	g_log->information("java detected: " + bool_as_text(java_present()));
	g_log->information("java_binary: " + m_java_binary);
	g_log->information("sdjagent_opts:" + m_sdjagent_opts);
	g_log->information("ssh.enabled: " + bool_as_text(m_ssh_enabled));
	g_log->information("sysdig.capture_enabled: " + bool_as_text(m_sysdig_capture_enabled));
	g_log->information("statsd enabled: " + bool_as_text(m_statsd_enabled));
	g_log->information("app_checks enabled: " + bool_as_text(m_app_checks_enabled));
	g_log->information("python binary: " + m_python_binary);
	g_log->information("known_ports: " + NumberFormatter::format(m_known_server_ports.count()));
	g_log->information("Kernel supports containers: " + bool_as_text(m_system_supports_containers));
	for(const auto& log_entry : m_k8s_logs)
	{
		g_log->log(log_entry.second, log_entry.first);
	}
	g_log->information("K8S autodetect enabled: " + bool_as_text(m_k8s_autodetect));
	g_log->information("K8S connection timeout [ms]: " + std::to_string(m_k8s_timeout_ms));

	if (!m_k8s_api_server.empty())
	{
		g_log->information("K8S API server: " + uri(m_k8s_api_server).to_string(false));
		if(m_k8s_delegated_nodes && uri(m_k8s_api_server).is_local() && !m_k8s_simulate_delegation)
		{
			m_k8s_delegated_nodes = 0;
			g_logger.log("K8s API server is local, k8s_delegated_nodes (" +
						 std::to_string(m_k8s_delegated_nodes) + ") ignored.", sinsp_logger::SEV_WARNING);
		}
	}
	if(m_k8s_simulate_delegation)
	{
		g_log->warning("!!! K8S delegation simulation enabled (non-production setting) !!!");
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
			g_log->information("Marathon groups API server: " + uri(marathon_uri).to_string(false));
			g_log->information("Marathon apps API server: " + uri(marathon_uri).to_string(false));
		}
	}
	else
	{
		g_log->information("Marathon API server not configured.");
	}
	g_log->information("Mesos autodetect enabled: " + bool_as_text(m_mesos_autodetect));
	g_log->information("Mesos connection timeout [ms]: " + std::to_string(m_mesos_timeout_ms));
	g_log->information("Mesos leader following enabled: " + bool_as_text(m_mesos_follow_leader));
	g_log->information("Marathon leader following enabled: " + bool_as_text(m_marathon_follow_leader));
	if(!m_mesos_credentials.first.empty())
	{
		g_log->information("Mesos credentials provided.");
	}
	if(!m_marathon_credentials.first.empty())
	{
		g_log->information("Marathon credentials provided.");
	}
	if(!m_dcos_enterprise_credentials.first.empty())
	{
		g_log->information("DC/OS Enterprise credentials provided.");
	}
	g_log->information("coredump enabled: " + bool_as_text(m_enable_coredump));
	g_log->information("Falco engine enabled: " + bool_as_text(m_enable_falco_engine));
	if(m_enable_falco_engine)
	{
		g_log->information("Falco engine default rules file: " + m_falco_default_rules_filename);
		g_log->information("Falco engine auto rules file: " + m_falco_auto_rules_filename);
		g_log->information("Falco engine rules file: " + m_falco_rules_filename);
		g_log->information("Falco disabled rule patterns: ");
		for(auto pattern : m_falco_engine_disabled_rule_patterns)
		{
			g_log->information("  " + pattern);
		}
		g_log->information("Falco engine sampling multiplier: " + NumberFormatter::format(m_falco_engine_sampling_multiplier));
	}

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
	if(m_auto_config)
	{
		g_log->information("Auto config enabled. File types and digests:");
		for (auto &pair : m_supported_auto_configs)
		{
			g_log->information("    " + pair.first + ": file digest: " + pair.second->digest());
		}
	}
	else
	{
		g_log->information("Auto config disabled");
	}
	if (m_emit_tracers)
	{
		g_log->information("Emitting sysdig tracers enabled");
	}
	if(m_mode == dragent_mode_t::NODRIVER)
	{
		g_log->information("Running in nodriver mode, Falco and Sysdig Captures will not work");
	}

	if(m_metrics_exclude.size())
	{
		std::ostringstream os;
		for(const auto& e : m_metrics_exclude)
		{
			os << std::endl << e;
		}
		g_log->information("Excluded metrics:" + os.str());
	}

	if(m_metrics_include.size())
	{
		std::ostringstream os;
		for(const auto& i : m_metrics_include)
		{
			os << std::endl << i;
		}
		g_log->information("Included metrics:" + os.str());
	}

	// Dump warnings+errors after the main config so they're more visible
	// Always keep these at the bottom
	for(const auto& item : m_config->warnings())
	{
		g_log->debug(item);
	}
	for(const auto& item : m_config->errors())
	{
		g_log->critical(item);
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
	auto udp_port = m_statsd_port;
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

int dragent_configuration::save_auto_config(const string &config_filename,
					    const string &config_data,
					    string &errstr)
{
	auto it = m_supported_auto_configs.find(config_filename);
	if (it == m_supported_auto_configs.end())
	{
		errstr = "Auto config filename " + config_filename +
			" is not a supported auto configuration file type";
		return -1;
	}

	return (it->second->save(*this, config_data, errstr));
}

void dragent_configuration::set_auto_config_directory(const string &config_directory)
{
	for (auto &it : m_supported_auto_configs)
	{
		it.second->set_config_directory(config_directory);
	}
}
