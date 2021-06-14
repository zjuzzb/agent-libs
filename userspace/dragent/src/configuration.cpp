#include "common_logger.h"
#include "command_line_manager.h"
#include "configuration.h"
#include "configuration_cli.h"
#include "json_error_log.h"
#include "network_utils.h"
#include "running_state.h"
#include "uri.h"
#include "windows_helpers.h"
#include "zlib.h"

#include "Poco/File.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/StreamCopier.h"
#ifdef CYGWING_AGENT
#include "proc_filter.h"
#endif

#include "configuration_manager.h"
#include "user_event_logger.h"

#include <sys/resource.h>
#include <sys/time.h>

using namespace std;
using namespace Poco;
using namespace Poco::Net;
using namespace network_utils;

COMMON_LOGGER("dragent");

std::atomic<bool> dragent_configuration::m_signal_dump(false);
std::atomic<bool> dragent_configuration::m_enable_trace(false);
std::atomic<bool> dragent_configuration::m_send_log_report(false);

type_config<std::string> dragent_configuration::c_root_dir(
    "/",
    "the root directory for all logs and other artifacts",
    "rootdir");

// By default we query aws endpoint 169.254.169.254 to get aws metadata
// This config option allows us to turn that on/off
type_config<bool> dragent_configuration::c_enable_aws_metadata(
	true,
	"Enables metadata collection from aws local endpoint",
	"collect_aws_metadata");

type_config<bool> c_restart_on_failed_config_update(
	true,
	"Restart on failed config update",
	"restart_on_failed_config_update");

namespace
{
std::string bool_as_text(bool b)
{
	return b ? "true" : "false";
}

/**
 * Helper to pass into the configuration manager since it
 * doesn't have access to the logger.
 */
void log_config(const ::std::string& value)
{
	LOG_INFO(value);
}

/**
 * Helper used by dragent_auto_configuration::save(), to parse the ofstream
 * error state into an errstr, and log a warning message
 */
void process_ofstream_error(ofstream& auto_config_f,
                            const string& config_filename,
                            const string& op_string,
                            int saved_errno,
                            string& errstr)
{
	std::ios::iostate iost = auto_config_f.rdstate();
	if (auto_config_f.bad())
	{
		errstr = string("Stream ") +
		         op_string +
		         string(" failed, bad_bit=1, iostate=") +
		         to_string(iost);
	}
	else if (auto_config_f.fail())
	{
		errstr = string("Stream ") +
		         op_string +
		         string(" failed, fail_bit=1, iostate=") +
		         to_string(iost);
	}
	else if (auto_config_f.eof())
	{
		errstr = string("Stream ") +
		         op_string +
		         string(" failed, eof_bit=1, iostate=") +
		         to_string(iost);
	}
	else
	{
		errstr = string("Stream ") +
		         op_string +
		         string(" failed, iostate=") +
		         to_string(iost);
	}

	// Log warning message for failed config file update
	LOG_WARNING("Config file %s: %s, errno=%d",
	            config_filename.c_str(),
	            errstr.c_str(),
	            saved_errno);
}

}  // namespace

dragent_auto_configuration::dragent_auto_configuration(const string& config_filename,
                                                       const string& config_directory,
                                                       const string& config_header)
    : m_config_filename(config_filename),
      m_config_directory(config_directory),
      m_config_header(config_header)
{
	init_digest();
}

int dragent_auto_configuration::save(dragent_configuration& config,
                                     const string& config_data,
                                     string& errstr)
{
	LOG_DEBUG(string("Received ") + m_config_filename + string(" with content: ") + config_data);
	m_sha1_engine.reset();
	if (!config_data.empty())
	{
		m_sha1_engine.update(m_config_header);
		m_sha1_engine.update(config_data);
	}
	auto new_digest = m_sha1_engine.digest();

	LOG_DEBUG(string("New digest=") + DigestEngine::digestToHex(new_digest) +
	          " old digest= " + DigestEngine::digestToHex(m_digest));

	if (new_digest != m_digest)
	{
		if (!validate(config_data, errstr))
		{
			return -1;
		}

		string path = config_path();

		if (config_data.empty())
		{
			File auto_config_f(path);
			auto_config_f.remove();
		}
		else
		{
			bool error_detected = false;
			int saved_errno;
			ofstream auto_config_f(path);

			auto_config_f << m_config_header << config_data;
			saved_errno = errno;

			if (!auto_config_f.good())
			{
				error_detected = true;

				process_ofstream_error(auto_config_f,
				                       m_config_filename.c_str(),
				                       "write",
				                       saved_errno,
				                       errstr);

				// If restart_on_failed_config_update == false, finish
				// cleanup and return error, skipping the call to
				// apply() below, which performs the process restart.
				if (c_restart_on_failed_config_update.get_value() == false)
				{
					LOG_INFO("Skipping restart after failed update of config file %s",
					         m_config_filename.c_str());
					auto_config_f.close();
					return -1;
				}

				// restart_on_failed_config_update == true, so we WILL
				// call apply() which performs a process restart.
				// Clear errstr for benefit of caller.
				errstr.clear();
			}

			if (!error_detected) {
				auto_config_f.flush();
				saved_errno = errno;

				if (!auto_config_f.good())
				{
					error_detected = true;

					process_ofstream_error(auto_config_f,
					                       m_config_filename.c_str(),
					                       "flush",
					                       saved_errno,
					                       errstr);

					// If restart_on_failed_config_update == false, finish
					// cleanup and return error, skipping the call to
					// apply() below, which performs the process restart.
					if (c_restart_on_failed_config_update.get_value() == false)
					{
						LOG_INFO("Skipping restart after failed update of config file %s",
						         m_config_filename.c_str());
						auto_config_f.close();
						return -1;
					}

					// restart_on_failed_config_update == true, so we WILL
					// call apply() which performs a process restart.
					// Clear errstr for benefit of caller.
					errstr.clear();
				}
			}

			auto_config_f.close();
			saved_errno = errno;

			if (!error_detected)
			{
				if (!auto_config_f.good())
				{
					process_ofstream_error(auto_config_f,
					                       m_config_filename.c_str(),
					                       "close",
					                       saved_errno,
					                       errstr);

					// If restart_on_failed_config_update == false, finish
					// cleanup and return error, skipping the call to
					// apply() below, which performs the process restart.
					if (c_restart_on_failed_config_update.get_value() == false)
					{
						LOG_INFO("Skipping restart after failed update of config file %s",
						         m_config_filename.c_str());
						return -1;
					}

					// skip_restart = false, so we WILL call apply()
					// which performs a process restart.
					// Clear errstr for benefit of caller.
					errstr.clear();
				}
			}
		}

		apply(config);
	}
	else
	{
		LOG_DEBUG("Auto config file is already up-to-date");
		return 0;
	}

	m_digest = new_digest;

	return 1;
}

void dragent_auto_configuration::init_digest()
{
	string path = config_path();

	m_sha1_engine.reset();

	if (path.size() > 0)
	{
		// Save initial digest
		File auto_config_file(path);
		if (auto_config_file.exists())
		{
			ifstream auto_config_f(auto_config_file.path());
			char readbuf[4096];
			while (auto_config_f.good())
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

void dragent_auto_configuration::set_config_directory(const std::string& config_directory)
{
	m_config_directory = config_directory;
	init_digest();
}

class dragent_yaml_auto_configuration : public dragent_auto_configuration
{
public:
	dragent_yaml_auto_configuration(const std::string& filename,
	                                const std::string& config_directory)
	    : dragent_auto_configuration(filename,
	                                 config_directory,
	                                 R"EOF(#
# WARNING: Sysdig Agent auto configuration, don't edit.
#          Please use "dragent.yaml" instead. To disable it, put
#          "auto_config: false" on "dragent.yaml" and then delete this file.
#
)EOF"),
	      m_forbidden_keys{"auto_config",
	                       "customerid",
	                       "collector",
	                       "collector_port",
	                       "ssl",
	                       "ssl_verify_certificate",
	                       "ca_certificate",
	                       "compression"}
	{
	}

	~dragent_yaml_auto_configuration() {}

	bool validate(const string& config_data, string& errstr)
	{
		if (config_data.empty())
		{
			return true;
		}

		yaml_configuration new_conf(config_data);
		if (!new_conf.errors().empty())
		{
			errstr = "New auto config is not valid, skipping it";
			return false;
		}
		for (const auto& key : m_forbidden_keys)
		{
			if (new_conf.get_scalar<string>(key, "default") != "default" ||
			    !new_conf.errors().empty())
			{
				errstr = "Overriding key=" + key + " on autoconfig is forbidden";
				return false;
			}
		}

		return true;
	}

	void apply(dragent_configuration& config)
	{
		LOG_INFO("New agent auto config file applied");
		dragent::running_state::instance().restart_for_config_update();
	}

private:
	const vector<string> m_forbidden_keys;
};

dragent_configuration::dragent_configuration()
	: m_min_console_priority((Message::Priority)-1)
	, m_min_file_priority((Message::Priority)-1)
	, m_min_event_priority((Message::Priority)-1)
	, m_globally_readable_log_files(false)
	, m_server_port(0)
	, m_ssl_enabled(false)
	, m_evtcnt(0)
	, m_config_test(false)
	, m_tracepoint_hits_threshold(0)
	, m_cpu_usage_max_sr_threshold(0.0)
	, m_autoupdate_enabled(true)
	, m_json_parse_errors_logfile("")
	, m_json_parse_errors_events_rate(0.00333)  // One event per 5 minutes
	, m_json_parse_errors_events_max_burst(10)
	, m_watchdog_enabled(true)
	, m_watchdog_sinsp_worker_timeout_s(0)
	, m_watchdog_sinsp_worker_debug_timeout_s(0)
	, m_watchdog_connection_manager_timeout_s(0)
	, m_watchdog_analyzer_tid_collision_check_interval_s(0)
	, m_watchdog_sinsp_data_handler_timeout_s(0)
#ifndef CYGWING_AGENT
	, m_watchdog_heap_profiling_interval_s(0)
#endif
	, m_dirty_shutdown_report_log_size_b(0)
	, m_capture_dragent_events(false)
	, m_jmx_sampling(1)
	, m_protocols_enabled(true)
	, m_protocols_truncation_size(0)
	, m_remotefs_enabled(false)
	, m_sysdig_capture_enabled(true)
	, m_max_sysdig_captures(1)
	, m_sysdig_capture_transmit_rate(1024 * 1024)
	, m_sysdig_capture_compression_level(Z_DEFAULT_COMPRESSION)
	, m_command_lines_capture_mode(sinsp_configuration::CM_TTY)
	, m_command_lines_include_container_healthchecks(false)
	, m_enable_coredump(false)
	, m_auto_config(true)
	, m_rlimit_msgqueue(posix_queue::min_msgqueue_limit())
	, m_user_events_rate(1)
	, m_user_max_burst_events(1000)
	, m_mode(dragent_mode_t::STANDARD)
	, m_snaplen(0)
	, m_query_docker_image_info(true)
	, m_load_error(false)
{
}

Message::Priority dragent_configuration::string_to_priority(const string& priostr)
{
	if (strncasecmp(priostr.c_str(), "emergency", 9) == 0)
	{
		return (Message::Priority)0;
	}
	else if (strncasecmp(priostr.c_str(), "alert", 5) == 0 ||
	         strncasecmp(priostr.c_str(), "fatal", 5) == 0)
	{
		return Message::PRIO_FATAL;
	}
	else if (strncasecmp(priostr.c_str(), "critical", 8) == 0)
	{
		return Message::PRIO_CRITICAL;
	}
	else if (strncasecmp(priostr.c_str(), "error", 5) == 0)
	{
		return Message::PRIO_ERROR;
	}
	else if (strncasecmp(priostr.c_str(), "warn", 4) == 0)
	{
		return Message::PRIO_WARNING;
	}
	else if (strncasecmp(priostr.c_str(), "notice", 6) == 0)
	{
		return Message::PRIO_NOTICE;
	}
	else if (strncasecmp(priostr.c_str(), "info", 4) == 0)
	{
		return Message::PRIO_INFORMATION;
	}
	else if (strncasecmp(priostr.c_str(), "debug", 5) == 0)
	{
		return Message::PRIO_DEBUG;
	}
	else if (strncasecmp(priostr.c_str(), "trace", 5) == 0)
	{
		return Message::PRIO_TRACE;
	}
	else if (priostr.empty() || strncasecmp(priostr.c_str(), "none", 4) == 0)
	{
		return (Message::Priority)-1;
	}
	else
	{
		throw sinsp_exception(
		    "Invalid log priority. Accepted values are: 'none', 'emergency', 'alert', 'critical', "
		    "'error', 'warning', 'notice', 'info', 'debug', 'trace'.");
	}
}

void dragent_configuration::add_percentiles()
{
	// TODO?
	// getting set directly compile fails in yaml-cpp:
	// error: incomplete type ‘YAML::convert<std::set<double> >’ used in nested name specifier
	// as a workaround, we get vector and copy it
	std::vector<double> pctls = m_config->get_scalar<std::vector<double>>("percentiles", {});
	if (pctls.size() > MAX_PERCENTILES)
	{
		m_ignored_percentiles.clear();
		std::copy(pctls.begin() + MAX_PERCENTILES,
		          pctls.end(),
		          std::back_inserter(m_ignored_percentiles));
		pctls.resize(MAX_PERCENTILES);
	}
	std::copy(pctls.begin(), pctls.end(), std::inserter(m_percentiles, m_percentiles.end()));
}

void dragent_configuration::sanitize_limits(filter_vec_t& filters)
{
	if (metric_limits::first_includes_all(filters))
	{
		filters.clear();
	}
	else  // if first rule is "exclude all", that's all we need
	{
		metric_limits::optimize_exclude_all(filters);
	}
	if (filters.size() > CUSTOM_METRICS_FILTERS_HARD_LIMIT)
	{
		filters.erase(filters.begin() + CUSTOM_METRICS_FILTERS_HARD_LIMIT, filters.end());
	}
}

void dragent_configuration::add_event_filter(user_event_filter_t::ptr_t& flt,
                                             const std::string& system,
                                             const std::string& component)
{
	if (!m_config)
	{
		return;
	}

	typedef std::set<string, ci_compare> seq_t;
	const auto& roots = m_config->get_roots();

	// shortcut to enable or disable all in dragent.yaml or dragent.auto.yaml (overriding default)
	seq_t user_events;
	for (const auto& root : roots)
	{
		user_events =
		    yaml_configuration::get_deep_sequence<seq_t>(*m_config, root, "events", system);
		if (user_events.size())
		{
			if (user_events.find("all") != user_events.end())
			{
				if (!flt)
				{
					flt = std::make_shared<user_event_filter_t>();
				}
				flt->add(user_event_meta_t({"all", {"all"}}));
				return;
			}
			else if (user_events.find("none") != user_events.end())
			{
				return;
			}
		}
	}

	// find the first user `events` across our files
	for (const auto& root : roots)
	{
		user_events = yaml_configuration::get_deep_sequence<seq_t>(*m_config,
		                                                           root,
		                                                           "events",
		                                                           system,
		                                                           component);
		if (!user_events.empty())
		{
			break;
		}
	}
	if (user_events.size())
	{
		if (user_events.find("none") == user_events.end())
		{
			if (!flt)
			{
				flt = std::make_shared<user_event_filter_t>();
			}
			if (user_events.find("all") != user_events.end())
			{
				flt->add(user_event_meta_t(component, {"all"}));
				return;
			}
			flt->add(user_event_meta_t(component, user_events));
		}
	}
}

string dragent_configuration::get_install_prefix(const Application* app)
{
#ifdef CYGWING_AGENT
	return windows_helpers::get_executable_parent_dir();
#else
	if (!app)  // during tests
	{
		return ".";
	}
	auto& config = app->config();
	auto path = config.getString("application.path");

	size_t dpos = path.rfind('/');
	if (dpos != string::npos)
	{
		string exedir = path.substr(0, dpos);

		dpos = exedir.rfind('/');
		if (dpos != string::npos)
		{
			return exedir.substr(0, dpos);
		}
	}

	return "";
#endif
}

void dragent_configuration::init(Application* app,
                                 bool use_installed_dragent_yaml,
                                 const std::string* conf_file_override_path)
{
	refresh_machine_id();
	std::string install_prefix = get_install_prefix(app);

	File package_dir(install_prefix);
	if (package_dir.exists() && use_installed_dragent_yaml)
	{
		m_default_root_dir = install_prefix;
		m_conf_file = Path(m_default_root_dir).append("etc").append("dragent.yaml").toString();
		m_defaults_conf_file =
		    Path(m_default_root_dir).append("etc").append("dragent.default.yaml").toString();
	}
	else
	{
#ifndef CYGWING_AGENT
		m_default_root_dir = Path::current();
		m_conf_file = Path(m_default_root_dir).append("dragent.yaml").toString();
		m_defaults_conf_file = Path(m_default_root_dir).append("dragent.default.yaml").toString();
#else
		m_default_root_dir = windows_helpers::get_executable_parent_dir();
		m_conf_file = Path(m_default_root_dir).append("etc").append("dragent.yaml").toString();
		m_defaults_conf_file =
		    Path(m_default_root_dir).append("etc").append("dragent.default.yaml").toString();
#endif
	}

	// Override m_conf_file to specified path if provided
	if ((conf_file_override_path != nullptr) && (!conf_file_override_path->empty()))
	{
		m_conf_file = *conf_file_override_path;
	}
	init();
}

void dragent_configuration::init()
{
	std::unique_ptr<dragent_auto_configuration> autocfg(
	    new dragent_yaml_auto_configuration("dragent.auto.yaml",
	                                        Path(m_default_root_dir).append("etc").toString()));
	std::unique_ptr<dragent_auto_configuration> injected_autocfg(
	    new dragent_yaml_auto_configuration("dragent.auto.injected.yaml",
	                                        Path(m_default_root_dir).append("etc").toString()));

	const string kubernetes_dragent_yaml =
	    m_default_root_dir + "/etc/kubernetes/config/dragent.yaml";
	if (m_auto_config)
	{
		m_config.reset(new yaml_configuration({m_conf_file,
		                                       kubernetes_dragent_yaml,
		                                       injected_autocfg->config_path(),
		                                       autocfg->config_path(),
		                                       m_defaults_conf_file}));
	}
	else
	{
		m_config.reset(
		    new yaml_configuration({m_conf_file, kubernetes_dragent_yaml, m_defaults_conf_file}));
	}

	configuration_cli::add("dragent", m_conf_file, {CLI_VIEW_CONFIGURATION});
	configuration_cli::add("configmap", kubernetes_dragent_yaml, {CLI_VIEW_CONFIGURATION});
	configuration_cli::add("backend", autocfg->config_path(), {CLI_VIEW_CONFIGURATION});
	configuration_cli::add("default", m_defaults_conf_file, {CLI_VIEW_CONFIGURATION});

	// The yaml_configuration catches exceptions so m_config will always be
	// a valid pointer, but set m_load_error so dragent will see the error
	if (!m_config->errors().empty())
	{
		m_load_error = true;
	}

	m_supported_auto_configs[string("dragent.auto.yaml")] =
	    unique_ptr<dragent_auto_configuration>(std::move(autocfg));

	m_supported_auto_configs[string("dragent.auto.injected.yaml")] =
	    unique_ptr<dragent_auto_configuration>(std::move(injected_autocfg));

	c_root_dir.set_default(m_default_root_dir);

	// init the configurations
	configuration_manager::instance().init_config(*m_config);
	metric_forwarding_configuration::instance().init();

	m_log_dir = Path(c_root_dir.get_value())
	                .append(m_config->get_scalar<string>("log", "location", "logs"))
	                .toString();

	m_log_rotate = m_config->get_scalar("log", "rotate", 10);

	m_max_log_size = m_config->get_scalar("log", "max_size", 10);

	m_globally_readable_log_files = m_config->get_scalar<bool>("log", "globally_readable", false);

	ifstream kubernetes_access_key(c_root_dir.get_value() + "/etc/kubernetes/secrets/access-key");
	if (kubernetes_access_key.good())
	{
		kubernetes_access_key >> m_customer_id;
	}
	if (m_customer_id.empty())
	{
		m_customer_id = m_config->get_scalar<string>("customerid", "");
	}

	if (m_server_addr.empty())
	{
		m_server_addr = m_config->get_scalar<string>("collector", "collector.sysdigcloud.com");
	}

	if (m_server_port == 0)
	{
		m_server_port = m_config->get_scalar<uint16_t>("collector_port", 6443);
	}

	m_machine_id_prefix = m_config->get_scalar<string>("machine_id_prefix", "");

	m_raw_file_priority = m_config->get_scalar<string>("log", "file_priority", "info");

	if (m_min_file_priority == -1)
	{
#ifdef _DEBUG
		m_min_file_priority =
		    string_to_priority(m_config->get_scalar<string>("log", "file_priority", "debug"));
#else
		m_min_file_priority =
		    string_to_priority(m_config->get_scalar<string>("log", "file_priority", "info"));
#endif
	}

	if (m_min_console_priority == -1)
	{
#ifdef _DEBUG
		m_min_console_priority =
		    string_to_priority(m_config->get_scalar<string>("log", "console_priority", "debug"));
#else
		m_min_console_priority =
		    string_to_priority(m_config->get_scalar<string>("log", "console_priority", "info"));
#endif
	}

	if (m_min_event_priority == -1)
	{
#ifdef _DEBUG
		m_min_event_priority =
		    string_to_priority(m_config->get_scalar<string>("log", "event_priority", "debug"));
#else
		m_min_event_priority =
		    string_to_priority(m_config->get_scalar<string>("log", "event_priority", "info"));
#endif
	}

	//
	// user-configured events
	//

	if (m_min_event_priority != -1)
	{
		// kubernetes
		add_event_filter(m_k8s_event_filter, "kubernetes", "node");
		add_event_filter(m_k8s_event_filter, "kubernetes", "pod");
		add_event_filter(m_k8s_event_filter, "kubernetes", "replicationController");
		add_event_filter(m_k8s_event_filter, "kubernetes", "replicaSet");
		add_event_filter(m_k8s_event_filter, "kubernetes", "daemonSet");
		add_event_filter(m_k8s_event_filter, "kubernetes", "deployment");
		add_event_filter(m_k8s_event_filter, "kubernetes", "statefulSet");
		add_event_filter(m_k8s_event_filter, "kubernetes", "service");
		add_event_filter(m_k8s_event_filter, "kubernetes", "horizontalPodAutoscalar");

		// docker
		add_event_filter(m_docker_event_filter, "docker", "container");
		add_event_filter(m_docker_event_filter, "docker", "image");
		add_event_filter(m_docker_event_filter, "docker", "volume");
		add_event_filter(m_docker_event_filter, "docker", "network");

		// containerd
		add_event_filter(m_containerd_event_filter, "containerd", "container");
		add_event_filter(m_containerd_event_filter, "containerd", "image");
	}

	add_percentiles();
	if (!m_percentiles.empty())
	{
		m_group_pctl_conf.reset(new proc_filter::group_pctl_conf());
		m_group_pctl_conf->set_enabled(
		    m_config->get_scalar<bool>("group_percentiles",
		                               "enabled",
		                               proc_filter::group_pctl_conf::enabled_default()));
		m_group_pctl_conf->set_check_interval(
		    m_config->get_scalar<uint32_t>("group_percentiles",
		                                   "check_interval",
		                                   proc_filter::group_pctl_conf::check_interval_default()));
		m_group_pctl_conf->set_max_containers(
		    m_config->get_scalar<uint32_t>("group_percentiles",
		                                   "max_containers",
		                                   proc_filter::group_pctl_conf::max_containers_default()));
		m_group_pctl_conf->set_rules(
		    m_config->get_first_deep_sequence<vector<object_filter_config::filter_rule>>(
		        "group_percentiles",
		        "process_filter"));
	}

	m_container_filter.reset(new proc_filter::conf("container_filter"));
	m_container_filter->set_enabled(m_config->get_scalar<bool>("use_container_filter", false));
	m_container_filter->set_rules(
	    m_config->get_first_deep_sequence<vector<object_filter_config::filter_rule>>(
	        "container_filter"));

	// Go user events are turned ON by default
	m_go_k8s_user_events = m_config->get_scalar<bool>("go_k8s_user_events", true);

	m_cointerface_cpu_profile_enabled =
	    m_config->get_scalar<bool>("cointerface_cpu_profile_enabled", false);
	m_cointerface_mem_profile_enabled =
	    m_config->get_scalar<bool>("cointerface_mem_profile_enabled", false);
	m_cointerface_events_per_profile =
	    m_config->get_scalar<int32_t>("cointerface_events_per_profile", 10000);
	m_cointerface_total_profiles = m_config->get_scalar<int32_t>("cointerface_total_profiles", 30);

	m_curl_debug = m_config->get_scalar<bool>("curl_debug", false);

	m_ssl_enabled = m_config->get_scalar<bool>("ssl", true);
	m_ssl_ca_certificate = Path(c_root_dir.get_value())
	                           .append(m_config->get_scalar<string>("ca_certificate", "root.cert"))
	                           .toString();

	m_ssl_ca_cert_paths = m_config->get_first_deep_sequence<vector<string>>("ca_cert_paths");
	std::string ssl_ca_cert_dir = m_config->get_scalar<string>("ca_cert_dir", "");
	if (!ssl_ca_cert_dir.empty())
	{
		m_ssl_ca_cert_paths.insert(m_ssl_ca_cert_paths.begin(), std::move(ssl_ca_cert_dir));
	}

	m_dump_dir = m_config->get_scalar<string>("dumpdir", "/tmp/");

	string command_lines_capture_mode_s =
	    m_config->get_scalar<string>("commandlines_capture", "capture_mode", "tty");
	if (command_lines_capture_mode_s == "tty")
	{
		m_command_lines_capture_mode = sinsp_configuration::command_capture_mode_t::CM_TTY;
	}
	else if (command_lines_capture_mode_s == "shell_ancestor")
	{
		m_command_lines_capture_mode =
		    sinsp_configuration::command_capture_mode_t::CM_SHELL_ANCESTOR;
	}
	else if (command_lines_capture_mode_s == "all")
	{
		m_command_lines_capture_mode = sinsp_configuration::command_capture_mode_t::CM_ALL;
	}
	m_command_lines_include_container_healthchecks =
	    m_config->get_scalar<bool>("commandlines_capture", "include_container_healthchecks", false);
	m_command_lines_valid_ancestors =
	    m_config->get_deep_merged_sequence<set<string>>("commandlines_capture", "valid_ancestors");

	m_tracepoint_hits_threshold = m_config->get_scalar<long>("tracepoint_hits_threshold", 0);
	m_tracepoint_hits_ntimes = m_config->get_scalar<unsigned>("tracepoint_hits_seconds", 5);
	m_cpu_usage_max_sr_threshold = m_config->get_scalar<double>("cpu_usage_max_sr_threshold", 0.0);
	m_cpu_usage_max_sr_ntimes = m_config->get_scalar<unsigned>("cpu_usage_max_sr_seconds", 5);

	m_autoupdate_enabled = m_config->get_scalar<bool>("autoupdate_enabled", true);
	m_json_parse_errors_logfile = m_config->get_scalar<string>("json_parse_errors_logfile", "");
	m_json_parse_errors_events_rate =
	    m_config->get_scalar<double>("json_parse_errors", "events_rate", 0.00333);
	m_json_parse_errors_events_max_burst =
	    m_config->get_scalar<uint32_t>("json_parse_errors", "events_max_burst", 10);
#ifdef _DEBUG
	m_watchdog_enabled = m_config->get_scalar<bool>("watchdog_enabled", false);
#else
	m_watchdog_enabled = m_config->get_scalar<bool>("watchdog_enabled", true);
#endif
	m_watchdog_sinsp_worker_timeout_s =
	    m_config->get_scalar<decltype(m_watchdog_sinsp_worker_timeout_s)>("watchdog",
	                                                                      "sinsp_worker_timeout_s",
	                                                                      60);
	m_watchdog_sinsp_worker_debug_timeout_s =
	    m_config->get_scalar<decltype(m_watchdog_sinsp_worker_debug_timeout_s)>(
	        "watchdog",
	        "sinsp_worker_debug_timeout_s",
	        55);
	m_watchdog_connection_manager_timeout_s =
	    m_config->get_scalar<decltype(m_watchdog_connection_manager_timeout_s)>(
	        "watchdog",
	        "connection_manager_timeout_s",
	        100);
	m_watchdog_subprocesses_logger_timeout_s =
		m_config->get_scalar<decltype(m_watchdog_subprocesses_logger_timeout_s)>(
			"watchdog",
			"subprocesses_logger_timeout_s",
			60);
	m_watchdog_timer_thread_timeout_s =
	    m_config->get_scalar<decltype(m_watchdog_timer_thread_timeout_s)>(
	        "watchdog",
	        "timer_thread_timeout_s",
	        60);
	m_watchdog_analyzer_tid_collision_check_interval_s =
	    m_config->get_scalar<decltype(m_watchdog_analyzer_tid_collision_check_interval_s)>(
	        "watchdog",
	        "analyzer_tid_collision_check_interval_s",
	        600);
	m_watchdog_sinsp_data_handler_timeout_s =
	    m_config->get_scalar<decltype(m_watchdog_sinsp_data_handler_timeout_s)>(
	        "watchdog",
	        "sinsp_data_handler_timeout_s",
	        60);

#ifndef CYGWING_AGENT
	m_watchdog_heap_profiling_interval_s =
	    m_config->get_scalar<decltype(m_watchdog_heap_profiling_interval_s)>(
	        "watchdog",
	        "heap_profiling_interval_s",
	        0);
#endif
	// Right now these two entries do not support merging between defaults and specified on config
	// file
	m_watchdog_max_memory_usage_subprocesses_mb =
	    m_config->get_scalar<ProcessValue64Map>("watchdog",
	                                            "max_memory_usage_subprocesses",
	                                            {{"sdchecks", 128U},
	                                             {"sdjagent", 256U},
	                                             {"mountedfs_reader", 32U},
	                                             {"statsite_forwarder", 32U},
	                                             {"cointerface", 1024U}});
	m_watchdog_subprocesses_timeout_s = m_config->get_scalar<ProcessValue64Map>(
	    "watchdog",
	    "subprocesses_timeout_s",
	    {{"sdchecks", 60U /* This should match the default timeout in sdchecks.py */},
	     {"sdjagent", 60U},
	     {"mountedfs_reader", 60U},
	     {"statsite_forwarder", 60U},
	     {"cointerface", 60U},
	     {"promex", 60U}});
	m_subprocesses_priority = m_config->get_scalar<ProcessValueMap>("subprocesses_priority",
	                                                                {{"sdchecks", 0},
	                                                                 {"sdjagent", 0},
	                                                                 {"mountedfs_reader", 0},
	                                                                 {"statsite_forwarder", 0},
	                                                                 {"cointerface", 0},
	                                                                 {"promex", 0}});

	m_dirty_shutdown_report_log_size_b =
	    m_config->get_scalar<decltype(m_dirty_shutdown_report_log_size_b)>("dirty_shutdown",
	                                                                       "report_log_size_b",
	                                                                       30 * 1024);
	m_dirty_shutdown_default_report_log_size_b = m_dirty_shutdown_report_log_size_b;
	m_dirty_shutdown_trace_report_log_size_b =
	    m_config->get_scalar<decltype(m_dirty_shutdown_trace_report_log_size_b)>(
	        "dirty_shutdown",
	        "trace_report_log_size_b",
	        300 * 1024);
	m_capture_dragent_events = m_config->get_scalar<bool>("capture_dragent_events", false);
	m_jmx_sampling = m_config->get_scalar<decltype(m_jmx_sampling)>("jmx", "sampling", 1);
	m_protocols_enabled = m_config->get_scalar<bool>("protocols", true);
	m_protocols_truncation_size = m_config->get_scalar<uint32_t>("protocols_truncation_size", 512);
	m_remotefs_enabled = m_config->get_scalar<bool>("remotefs", false);
	auto java_home = m_config->get_scalar<string>("java_home", "");
	for (const auto& bin_path :
	     {string("/usr/bin/java"), java_home + "/jre/bin/java", java_home + "/bin/java"})
	{
		if (is_executable(bin_path))
		{
			m_java_binary = bin_path;
			break;
		}
	}
	m_sdjagent_opts = m_config->get_scalar<string>("sdjagent_opts", "-Xmx256m");
	m_sysdig_capture_enabled = m_config->get_scalar<bool>("sysdig_capture_enabled", true);
	m_max_sysdig_captures = m_config->get_scalar<uint32_t>("sysdig capture", "max outstanding", 1);
	m_sysdig_capture_transmit_rate =
	    m_config->get_scalar<double>("sysdig capture", "transmit rate", 1024 * 1024);
	m_sysdig_capture_compression_level =
	    m_config->get_scalar<int32_t>("sysdig capture", "compression level", Z_DEFAULT_COMPRESSION);
	if (m_sysdig_capture_compression_level < Z_DEFAULT_COMPRESSION ||
	    m_sysdig_capture_compression_level > Z_BEST_COMPRESSION)
	{
		LOG_WARNING("Invalid compression level " +
		            std::to_string(m_sysdig_capture_compression_level) + ". Setting to " +
		            std::to_string(Z_DEFAULT_COMPRESSION) + ".");
		m_sysdig_capture_compression_level = Z_DEFAULT_COMPRESSION;
	}

	m_app_checks = m_config->get_merged_sequence<app_check>("app_checks");

	// Filter out disabled checks
	unordered_set<string> disabled_checks;
	for (const auto& item : m_app_checks)
	{
		if (!item.enabled())
		{
			disabled_checks.emplace(item.name());
		}
	}
	m_app_checks.erase(remove_if(m_app_checks.begin(),
	                             m_app_checks.end(),
	                             [&disabled_checks](const app_check& item) {
		                             return disabled_checks.find(item.name()) !=
		                                    disabled_checks.end();
	                             }),
	                   m_app_checks.end());

#ifndef CYGWING_AGENT
	// Prometheus
	m_prom_conf.set_enabled(m_config->get_scalar<bool>("prometheus", "enabled", false));
	m_prom_conf.set_log_errors(m_config->get_scalar<bool>("prometheus", "log_errors", false));
	m_prom_conf.set_interval(m_config->get_scalar<int>("prometheus", "interval", -1));
	m_prom_conf.set_max_metrics_per_proc(
	    m_config->get_scalar<int>("prometheus", "max_metrics_per_process", -1));
	m_prom_conf.set_max_tags_per_metric(
	    m_config->get_scalar<int>("prometheus", "max_tags_per_metric", -1));
	m_prom_conf.set_rules(
	    m_config->get_first_deep_sequence<vector<object_filter_config::filter_rule>>(
	        "prometheus",
	        "process_filter"));
	m_prom_conf.set_host_rules(
	    m_config->get_first_deep_sequence<vector<object_filter_config::filter_rule>>(
	        "prometheus",
	        "remote_services"));
	m_prom_conf.set_histograms(m_config->get_scalar<bool>("prometheus", "histograms", false));
	m_prom_conf.set_ingest_raw(m_config->get_scalar<bool>("prometheus", "ingest_raw", false));
	m_prom_conf.set_ingest_calculated(
	    m_config->get_scalar<bool>("prometheus", "ingest_calculated", true));
	m_prom_conf.set_prom_sd(
	    m_config->get_scalar<bool>("prometheus", "prom_service_discovery", false));
	m_prom_conf.set_metric_expiration(
	    m_config->get_scalar<int>("prometheus", "metric_expiration", 300));

	// custom container engines
	try
	{
		m_custom_container.set_cgroup_match(
		    m_config->get_scalar<string>("custom_container", "match", "cgroup", ""));
		m_custom_container.set_environ_match(
		    m_config->get_first_deep_map<string>("custom_container", "match", "environ"));
		m_custom_container.set_id_pattern(
		    m_config->get_scalar<string>("custom_container", "id", ""));
		m_custom_container.set_name_pattern(
		    m_config->get_scalar<string>("custom_container", "name", ""));
		m_custom_container.set_image_pattern(
		    m_config->get_scalar<string>("custom_container", "image", ""));
		m_custom_container.set_label_pattern(
		    m_config->get_first_deep_map<string>("custom_container", "labels"));
		m_custom_container.set_max(m_config->get_scalar<int>("custom_container", "limit", 50));
		m_custom_container.set_max_id_length(
		    m_config->get_scalar<int>("custom_container", "max_id_length", 12));
		m_custom_container.set_incremental_metadata(
		    m_config->get_scalar<bool>("custom_container", "incremental_metadata", false));
		m_custom_container.set_enabled(
		    m_config->get_scalar<bool>("custom_container", "enabled", false));
	}
	catch (const Poco::RuntimeException& e)
	{
		m_config->add_error("config file error inside key custom_containers: " + e.message() +
		                    ", disabling custom container support");
		m_custom_container.set_enabled(false);
	}

	// Prometheus exporter
	m_promex_enabled = m_config->get_scalar<bool>("prometheus_exporter", "enabled", false);
	m_promex_url =
	    m_config->get_scalar<string>("prometheus_exporter", "listen_url", "0.0.0.0:9544");
	m_promex_connect_url = m_config->get_scalar<string>("prometheus_exporter", "connect_url", "");
	m_promex_container_labels = m_config->get_scalar<string>("prometheus_exporter",
	                                                         "container_labels",
	                                                         m_custom_container.get_labels());

#endif  // CYGWING_AGENT

	vector<string> default_pythons = {"/usr/bin/python3.9",
					  "/usr/bin/python3.8",
					  "/usr/bin/python3.7",
					  "/usr/bin/python3.6",
					  "/usr/bin/python3.5",
	                                  "/usr/bin/python2.7",
	                                  "/usr/bin/python27",
					  "/usr/bin/python3",
	                                  "/usr/bin/python2",
	                                  "/usr/bin/python2.6",
	                                  "/usr/bin/python26"};
	auto python_binary_path = m_config->get_scalar<string>("python_binary", "");
	if (!python_binary_path.empty() && is_executable(python_binary_path))
	{
		m_python_binary = python_binary_path;
	}
	else
	{
		for (const auto& python : default_pythons)
		{
			if (is_executable(python))
			{
				m_python_binary = python;
				break;
			}
		}
	}

	m_containers_labels_max_len =
	    m_config->get_scalar<uint32_t>("containers", "labels_max_len", 100);
	m_container_patterns = m_config->get_scalar<vector<string>>("containers", "include", {});

	for (const auto& root : m_config->get_roots())
	{
		const auto& node = root["chisels"];
		if (!node.IsSequence())
		{
			break;
		}
		for (auto ch : node)
		{
			sinsp_chisel_details details;

			try
			{
				details.m_name = ch["name"].as<string>();

				for (auto arg : ch["args"])
				{
					details.m_args.push_back(pair<string, string>(arg.first.as<string>().c_str(),
					                                              arg.second.as<string>().c_str()));
				}

				m_chisel_details.push_back(details);
			}
			catch (const YAML::BadConversion& ex)
			{
				throw sinsp_exception("config file error at key: chisels");
			}
		}
	}

#ifndef CYGWING_AGENT
	// K8s
	// new_k8s takes precedence over dev_new_k8s but still turn it on
	// if all they specify is "dev_new_k8s: true"
	m_use_new_k8s = m_config->get_scalar<bool>("dev_new_k8s", true);
	m_use_new_k8s = m_config->get_scalar<bool>("new_k8s", m_use_new_k8s);
	m_k8s_cluster_name = m_config->get_scalar<string>("k8s_cluster_name", "");
	m_k8s_local_update_frequency = m_config->get_scalar<uint16_t>("k8s_local_update_frequency", 1);
	m_k8s_cluster_update_frequency =
	    m_config->get_scalar<uint16_t>("k8s_cluster_update_frequency", 1);
	// >0 to set the number of delegated nodes
	// 0 to disable delegation
	// <0 to force delegation
	m_k8s_delegated_nodes = m_config->get_scalar<int>("k8s_delegated_nodes", 2);

	auto k8s_extensions_v =
	    m_config->get_merged_sequence<k8s_ext_list_t::value_type>("k8s_extensions");
	m_k8s_extensions = k8s_ext_list_t(k8s_extensions_v.begin(), k8s_extensions_v.end());

	// go_k8s_user_events need new_k8s enabled
	if (m_go_k8s_user_events && !m_use_new_k8s)
	{
		m_config->add_warning("Disabling go_k8s_user_events because new_k8s is disabled");
		m_go_k8s_user_events = false;
	}

	// End K8s

	// Mesos
	m_mesos_state_uri = m_config->get_scalar<string>("mesos_state_uri", "");
	auto marathon_uris = m_config->get_merged_sequence<string>("marathon_uris");
	for (auto u : marathon_uris)
	{
		m_marathon_uris.push_back(u);
	}
	m_mesos_autodetect = m_config->get_scalar<bool>("mesos_autodetect", true);
	m_mesos_timeout_ms = m_config->get_scalar<int>("mesos_timeout_ms", 10000);
	m_mesos_follow_leader =
	    m_config->get_scalar<bool>("mesos_follow_leader",
	                               m_mesos_state_uri.empty() && m_mesos_autodetect ? true : false);
	m_marathon_follow_leader =
	    m_config->get_scalar<bool>("marathon_follow_leader",
	                               marathon_uris.empty() && m_mesos_autodetect ? true : false);
	m_mesos_credentials.first = m_config->get_scalar<std::string>("mesos_user", "");
	m_mesos_credentials.second = m_config->get_scalar<std::string>("mesos_password", "");
	m_marathon_credentials.first = m_config->get_scalar<std::string>("marathon_user", "");
	m_marathon_credentials.second = m_config->get_scalar<std::string>("marathon_password", "");
	m_dcos_enterprise_credentials.first = m_config->get_scalar<std::string>("dcos_user", "");
	m_dcos_enterprise_credentials.second = m_config->get_scalar<std::string>("dcos_password", "");

	std::vector<std::string> default_skip_labels = {"DCOS_PACKAGE_METADATA",
	                                                "DCOS_PACKAGE_COMMAND"};
	auto marathon_skip_labels_v =
	    m_config->get_merged_sequence<std::string>("marathon_skip_labels", default_skip_labels);
	m_marathon_skip_labels =
	    std::set<std::string>(marathon_skip_labels_v.begin(), marathon_skip_labels_v.end());
#endif
	// End Mesos

	m_enable_coredump = m_config->get_scalar<bool>("coredump", false);
	m_rlimit_msgqueue = m_config->get_scalar<unsigned long>("msgqueue_limit", m_rlimit_msgqueue);
	if (m_rlimit_msgqueue < posix_queue::min_msgqueue_limit())
	{
		// cannot log a warning here
		m_rlimit_msgqueue = posix_queue::min_msgqueue_limit();
	}
	m_user_events_rate = m_config->get_scalar<uint64_t>("events", "rate", 1);
	m_user_max_burst_events = m_config->get_scalar<uint64_t>("events", "max_burst", 1000);

	auto suppressed_comms = m_config->get_merged_sequence<string>("skip_events_by_process");
	for (auto& comm : suppressed_comms)
	{
		m_suppressed_comms.push_back(comm);
	}
#ifndef CYGWING_AGENT
	auto supp_type_strs = m_config->get_merged_sequence<string>("skip_events_by_type");
	sinsp_utils::parse_suppressed_types(supp_type_strs, &m_suppressed_types);
#endif

	m_mounts_filter = m_config->get_merged_sequence<user_configured_filter>("mounts_filter");
	m_mounts_limit_size = m_config->get_scalar<unsigned>("mounts_limit_size", 15u);

	// Check existence of namespace to see if kernel supports containers
	File nsfile("/proc/self/ns/mnt");
	m_system_supports_containers = (m_mounts_limit_size > 0) && nsfile.exists();

	m_auto_config = m_config->get_scalar("auto_config", true);
	m_emit_tracers = m_config->get_scalar("emit_tracers", true);
	m_enable_grpc_tracing = m_config->get_scalar("enable_grpc_tracing", false);

	// need to find out if it's explicitly set so we can forward it to
	// the configs used by feature manager.
	std::string mode_s;
	uint32_t priority = m_config->get_scalar_depth<string>("run_mode", mode_s);
	if (priority == -1)
	{
		mode_s = "standard";
	}

	if (mode_s == "nodriver")
	{
		m_mode = dragent_mode_t::NODRIVER;
		m_sysdig_capture_enabled = false;
	}
	else if (mode_s == "simpledriver")
	{
		m_mode = dragent_mode_t::SIMPLEDRIVER;
	}
	m_mode_explicitly_set = (priority != -1);

	m_excess_metric_log = m_config->get_scalar("metrics_excess_log", false);
	m_metrics_cache = m_config->get_scalar<unsigned>("metrics_cache_size", 0u);
	m_metrics_filter = m_config->get_merged_sequence<user_configured_filter>("metrics_filter");
	// if first filter entry is empty or '*' and included, everything will be allowed, so it's
	// pointless to have the filter list
	sanitize_limits(m_metrics_filter);

	// get label filters
	m_labels_filter =
	    m_config->get_merged_sequence<user_configured_filter>("container_labels_filter");
	m_labels_cache = m_config->get_scalar<uint16_t>("container_labels_cache_size", 0u);
	m_excess_labels_log = m_config->get_scalar("container_labels_excess_log", false);
	sanitize_limits(m_labels_filter);

	// K8s tags filter
	m_k8s_filter = m_config->get_merged_sequence<user_configured_filter>("k8s_labels_filter");
	m_k8s_cache_size = m_config->get_scalar<uint16_t>("k8s_labels_cache_size", 0u);
	m_excess_k8s_log = m_config->get_scalar("k8s_labels_excess_log", false);
	sanitize_limits(m_k8s_filter);

	m_stress_tools = m_config->get_merged_sequence<string>("perf_sensitive_programs");
	m_detect_stress_tools = !m_stress_tools.empty();
	m_coclient_max_loop_evts =
	    m_config->get_scalar<uint32_t>("coclient_max_loop_evts", m_coclient_max_loop_evts);

	m_snaplen = m_config->get_scalar<unsigned>("snaplen", 0);
	m_monitor_files_freq_sec =
	    m_config->get_scalar<unsigned>("monitor_files", "check_frequency_s", 0);
	auto monitor_files =
	    m_config->get_deep_merged_sequence<vector<string>>("monitor_files", "files");
	for (auto& file : monitor_files)
	{
		if (file.find('/') != 0)
		{
			file = c_root_dir.get_value() + '/' + file;
		}
		m_monitor_files.insert(file);
	}

	// options related to batching of cointerface msgs
	m_query_docker_image_info = m_config->get_scalar<bool>("query_docker_image_info", true);

	m_flush_log_time =
	    m_config->get_scalar<uint64_t>("flush_tracers", "timeout_ms", 1000) * 1000000;
	m_flush_log_time_duration =
	    m_config->get_scalar<uint64_t>("flush_tracers", "duration_ms", 10000) * 1000000;
	m_flush_log_time_cooldown =
	    m_config->get_scalar<uint64_t>("flush_tracers", "cooldown_ms", 600000) * 1000000;

	m_top_connections_in_sample =
	    m_config->get_scalar<uint32_t>("top_connections_in_sample", TOP_CONNECTIONS_IN_SAMPLE);
	m_max_n_external_clients =
	    m_config->get_scalar<uint32_t>("max_n_external_clients", MAX_N_EXTERNAL_CLIENTS);
	m_top_processes_in_sample =
	    m_config->get_scalar<int32_t>("top_processes_in_sample", TOP_PROCESSES_IN_SAMPLE);
	m_top_processes_per_container =
	    m_config->get_scalar<int32_t>("top_processes_per_container", TOP_PROCESSES_PER_CONTAINER);
	m_report_source_port = m_config->get_scalar<bool>("report_source_port", false);

	// URL filter configs
	auto url_groups_v = m_config->get_merged_sequence<std::string>("url_groups");
	m_url_groups = std::set<std::string>(url_groups_v.begin(), url_groups_v.end());
	m_url_groups_enabled = m_config->get_scalar<bool>("url_grouping_enabled", false);

	m_track_connection_status = m_config->get_scalar<bool>("track_connection_status", false);
	m_connection_truncate_report_interval =
	    m_config->get_scalar<int>("connection_table", "truncation_report_interval", 0);
	m_connection_truncate_log_interval =
	    m_config->get_scalar<int>("connection_table", "truncation_log_interval", 0);

	m_username_lookups = m_config->get_scalar<bool>("username_lookups", false);

	m_track_environment = m_config->get_scalar<bool>("environment_tracking", "enabled", false);
	m_envs_per_flush = m_config->get_scalar<uint32_t>("environment_tracking", "max_per_flush", 3);
	m_max_env_size = m_config->get_scalar<size_t>("environment_tracking", "max_size", 8192);
	m_env_blacklist = make_unique<env_hash::regex_list_t>();
	for (const auto& regex :
	     m_config->get_deep_merged_sequence<vector<string>>("environment_tracking", "blacklist"))
	{
		m_env_blacklist->emplace_back(regex);
	}
	m_env_hash_ttl = m_config->get_scalar<uint64_t>("environment_tracking", "hash_ttl", 86400);
	m_env_metrics = m_config->get_scalar<bool>("environment_tracking", "send_metrics", true);
	m_env_audit_tap = m_config->get_scalar<bool>("environment_tracking", "send_audit_tap", true);
	m_large_envs = m_config->get_scalar<bool>("enable_large_environments", false);

	m_audit_tap_enabled = m_config->get_scalar<bool>("audit_tap", "enabled", false);

	m_top_files_per_prog = m_config->get_scalar<int>("top_files", "per_program", 0);
	m_top_files_per_container = m_config->get_scalar<int>("top_files", "per_container", 0);
	m_top_files_per_host = m_config->get_scalar<int>("top_files", "per_host", TOP_FILES_IN_SAMPLE);

	m_top_file_devices_per_prog = m_config->get_scalar<int>("top_file_devices", "per_program", 0);
	m_top_file_devices_per_container =
	    m_config->get_scalar<int>("top_file_devices", "per_container", 0);
	m_top_file_devices_per_host = m_config->get_scalar<int>("top_file_devices", "per_host", 0);

	if (!m_audit_tap_enabled)
	{
		m_env_audit_tap = false;
	}
	if (!m_env_metrics && !m_env_audit_tap)
	{
		m_track_environment = false;
	}
	m_procfs_scan_procs = m_config->get_first_deep_sequence<set<string>>("procfs_scan_procs");

	m_secure_audit_k8s_active_filters =
	    m_config->get_first_deep_sequence<vector<string>>("secure_audit_streams",
	                                                      "k8s_active_filters");

	for (auto it : m_secure_audit_k8s_active_filters)
	{
		m_secure_audit_k8s_filters[it] =
		    m_config->get_first_deep_map<string>("secure_audit_streams", "k8s_filters", it);
	}
}

void dragent_configuration::print_configuration() const
{
	LOG_INFO("Distribution: " + get_distribution());
	LOG_INFO("machine id: " + m_machine_id_prefix + m_machine_id);
	LOG_INFO("rootdir: " + c_root_dir.get_value());
	LOG_INFO("conffile: " + m_conf_file);
	LOG_INFO("log.location: " + m_log_dir);
	LOG_INFO("log.globally_readable: %s", m_globally_readable_log_files ? "true" : "false");
	LOG_INFO("collector: " + m_server_addr);
	LOG_INFO("collector_port: " + NumberFormatter::format(m_server_port));
	LOG_INFO("log.file_priority: " + NumberFormatter::format(m_min_file_priority));
	LOG_INFO("log.console_priority: " + NumberFormatter::format(m_min_console_priority));
	LOG_INFO("log.event_priority: " + NumberFormatter::format(m_min_event_priority));
	LOG_INFO("CURL debug: " + bool_as_text(m_curl_debug));
	LOG_INFO("ssl: " + bool_as_text(m_ssl_enabled));
	LOG_INFO("ca_certificate: " + m_ssl_ca_certificate);
	if (!m_ssl_ca_cert_paths.empty())
	{
		string ca_cert_paths("ca_cert_paths:");
		for (const auto& path : m_ssl_ca_cert_paths)
		{
			ca_cert_paths.append(" " + path);
		}
		LOG_INFO(ca_cert_paths);
	}
	LOG_INFO("secure_audit_streams: ");
	LOG_INFO("secure_audit_streams.k8s_active_filters:");
	for (auto it : m_secure_audit_k8s_active_filters)
	{
		LOG_INFO("  - " + it);
	}
	LOG_INFO("secure_audit_streams.k8s_filters:");
	for (auto it : m_secure_audit_k8s_filters)
	{
		LOG_INFO("  " + it.first + ":");
		for (auto it2 : it.second)
		{
			LOG_INFO("    " + it2.first + " : " + it2.second);
		}
	}
	LOG_INFO("dumpdir: " + m_dump_dir);
	LOG_INFO("commandlines_capture.capture_mode: " +
	         NumberFormatter::format(m_command_lines_capture_mode));
	LOG_INFO("Will" + string((m_command_lines_include_container_healthchecks ? " " : " not")) +
	         " include container health checks in collected commandlines");
	string ancestors;
	for (auto s : m_command_lines_valid_ancestors)
	{
		ancestors.append(s + " ");
	}
	LOG_INFO("commandlines_capture.valid_ancestors: " + ancestors);
	LOG_INFO("absorb_event_bursts: " + bool_as_text(m_detect_stress_tools));
	if (m_tracepoint_hits_threshold > 0)
	{
		LOG_INFO(
		    "tracepoint_hits_threshold: " + NumberFormatter::format(m_tracepoint_hits_threshold) +
		    " seconds=" + NumberFormatter::format(m_tracepoint_hits_ntimes));
	}
	if (m_cpu_usage_max_sr_threshold > 0)
	{
		LOG_INFO(
		    "cpu_usage_max_sr_threshold: " + NumberFormatter::format(m_cpu_usage_max_sr_threshold) +
		    " seconds=" + NumberFormatter::format(m_cpu_usage_max_sr_ntimes));
	}
	LOG_INFO("autoupdate_enabled: " + bool_as_text(m_autoupdate_enabled));
	if (m_json_parse_errors_logfile != "")
	{
		LOG_INFO("Will log json parse errors to; " + m_json_parse_errors_logfile);
		g_json_error_log.set_json_parse_errors_file(m_json_parse_errors_logfile);
	}
	g_json_error_log.set_machine_id(m_machine_id_prefix + m_machine_id);
	g_json_error_log.set_events_rate(m_json_parse_errors_events_rate,
	                                 m_json_parse_errors_events_max_burst);
	LOG_INFO("watchdog_enabled: " + bool_as_text(m_watchdog_enabled));
	LOG_INFO("watchdog.sinsp_worker_timeout_s: " +
	         NumberFormatter::format(m_watchdog_sinsp_worker_timeout_s));
	LOG_INFO("watchdog.connection_manager_timeout_s: " +
	         NumberFormatter::format(m_watchdog_connection_manager_timeout_s));
	LOG_INFO("watchdog.subprocesses_logger_timeout_s: " +
	         NumberFormatter::format(m_watchdog_subprocesses_logger_timeout_s));
	LOG_INFO("watchdog.analyzer_tid_collision_check_interval_s: " +
	         NumberFormatter::format(m_watchdog_analyzer_tid_collision_check_interval_s));
	LOG_INFO("watchdog.sinsp_data_handler_timeout_s: " +
	         NumberFormatter::format(m_watchdog_sinsp_data_handler_timeout_s));
#ifndef CYGWING_AGENT
	LOG_INFO("watchdog.heap_profiling_interval_s: " +
	         NumberFormatter::format(m_watchdog_heap_profiling_interval_s));
#endif
	LOG_INFO("dirty_shutdown.report_log_size_b: " +
	         NumberFormatter::format(m_dirty_shutdown_report_log_size_b));
	LOG_INFO("capture_dragent_events: " + bool_as_text(m_capture_dragent_events));
	LOG_INFO("User events rate: " + NumberFormatter::format(m_user_events_rate));
	LOG_INFO("User events max burst: " + NumberFormatter::format(m_user_max_burst_events));
	LOG_INFO("containers: labels max len: " + NumberFormatter::format(m_containers_labels_max_len) +
	         " characters");
	if (m_percentiles.size())
	{
		std::ostringstream os;
		os << '[';
		for (const auto& p : m_percentiles)
		{
			os << p << ',';
		}
		os.seekp(-1, os.cur);
		os << ']';
		LOG_INFO("Percentiles: " + os.str());
		LOG_INFO("Group Percentiles: " + bool_as_text(m_group_pctl_conf->enabled()));
		if (m_group_pctl_conf->enabled())
		{
			LOG_INFO("  Check interval: " +
			         NumberFormatter::format(m_group_pctl_conf->check_interval()));
			LOG_INFO("  Max containers: " +
			         NumberFormatter::format(m_group_pctl_conf->max_containers()));
		}
	}
	else
	{
		LOG_INFO("Percentiles: " + bool_as_text(false));
	}
	if (m_ignored_percentiles.size())
	{
		std::ostringstream os;
		os << "Percentiles ignored (max allowed " + std::to_string(MAX_PERCENTILES) + "): [";
		for (const auto& p : m_ignored_percentiles)
		{
			os << p << ',';
		}
		os.seekp(-1, os.cur);
		os << ']';
		LOG_WARNING(os.str());
		sinsp_user_event::tag_map_t tags;
		tags["source"] = "dragent";

		auto evt = sinsp_user_event(get_epoch_utc_seconds_now(),
		                            std::string("PercentileLimitExceeded"),
		                            std::string(os.str()),
		                            std::string(),
		                            std::move(tags),
		                            user_event_logger::SEV_EVT_WARNING);

		user_event_logger::log(evt, user_event_logger::SEV_EVT_WARNING);
	}
	LOG_INFO("protocols: " + bool_as_text(m_protocols_enabled));
	LOG_INFO("protocols_truncation_size: " + NumberFormatter::format(m_protocols_truncation_size));
	LOG_INFO("remotefs: " + bool_as_text(m_remotefs_enabled));
	LOG_INFO("jmx.sampling: " + NumberFormatter::format(m_jmx_sampling));
	// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
	LOG_INFO("java detected: " + bool_as_text(java_present()));
	LOG_INFO("java_binary: " + m_java_binary);
	LOG_INFO("sdjagent_opts:" + m_sdjagent_opts);
	if (m_config->get_scalar<bool>("jmx", "enabled", false) && getppid() == 1)
	{
		LOG_WARNING(
		    "Sysdig Agent container has been launched without `--pid host` parameter, JMX metrics "
		    "will not be available");
	}
	LOG_INFO("sysdig.capture_enabled: " + bool_as_text(m_sysdig_capture_enabled));
	LOG_INFO("sysdig capture.max outstanding: " + NumberFormatter::format(m_max_sysdig_captures));
	LOG_INFO("sysdig capture.transmit rate (bytes/sec): " +
	         NumberFormatter::format(m_sysdig_capture_transmit_rate));
	LOG_INFO("sysdig capture.compression level: " +
	         NumberFormatter::format(m_sysdig_capture_compression_level));
#ifndef CYGWING_AGENT
	LOG_INFO("prometheus autodetection enabled: " + bool_as_text(m_prom_conf.enabled()));
	LOG_INFO("prometheus service discovery enabled: " + bool_as_text(m_prom_conf.prom_sd()));
	if (m_prom_conf.enabled())
	{
		LOG_INFO("prometheus histograms enabled: " + bool_as_text(m_prom_conf.histograms()));
	}
	LOG_INFO("prometheus exporter enabled: " + bool_as_text(m_promex_enabled));
	if (m_promex_enabled)
	{
		LOG_INFO("prometheus exporter listen address: " + m_promex_url);
		if (!m_promex_connect_url.empty())
		{
			LOG_INFO("external prometheus exporter address: " + m_promex_connect_url);
		}
		else
		{
			LOG_INFO("internal prometheus exporter started as subprocess");
		}
		LOG_INFO("prometheus exporter container labels: " + m_promex_container_labels);
	}
#endif
	LOG_INFO("python binary: " + m_python_binary);
	LOG_INFO("Kernel supports containers: " + bool_as_text(m_system_supports_containers));
	if (m_k8s_delegated_nodes)
	{
		LOG_INFO("K8S delegated nodes: " + std::to_string(m_k8s_delegated_nodes));
	}
	if (!m_k8s_extensions.empty())
	{
		std::ostringstream os;
		os << std::endl;
		for (const auto& ext : m_k8s_extensions)
		{
			os << ext << std::endl;
		}
		LOG_INFO("K8S extensions:" + os.str());
	}
	if (m_use_new_k8s)
	{
		LOG_INFO("Use new K8s integration");
		LOG_INFO("K8s metadata local update frequency: %d", m_k8s_local_update_frequency);
		LOG_INFO("K8s metadata cluster update frequency: %d", m_k8s_cluster_update_frequency);
	}
	if (!m_k8s_cluster_name.empty())
	{
		LOG_INFO("K8s cluster name: " + m_k8s_cluster_name);
	}
	if (!m_aws_metadata.m_instance_id.empty())
	{
		LOG_INFO("AWS instance-id: " + m_aws_metadata.m_instance_id);
	}
	if (m_aws_metadata.m_public_ipv4)
	{
		LOG_INFO("AWS public-ipv4: " + NumberFormatter::format(m_aws_metadata.m_public_ipv4));
	}
	if (!m_aws_metadata.m_account_id.empty())
	{
		LOG_INFO("AWS account-id: " + m_aws_metadata.m_account_id);
	}
	if (!m_aws_metadata.m_region.empty())
	{
		LOG_INFO("AWS region: " + m_aws_metadata.m_region);
	}
	if (!m_mesos_state_uri.empty())
	{
		LOG_INFO("Mesos state API server: " + m_mesos_state_uri);
	}
#ifndef CYGWING_AGENT
	if (!m_marathon_uris.empty())
	{
		for (const auto& marathon_uri : m_marathon_uris)
		{
			LOG_INFO("Marathon groups API server: " + uri(marathon_uri).to_string(false));
			LOG_INFO("Marathon apps API server: " + uri(marathon_uri).to_string(false));
		}
	}
	else
	{
		LOG_INFO("Marathon API server not configured.");
	}
	LOG_INFO("Mesos autodetect enabled: " + bool_as_text(m_mesos_autodetect));
	LOG_INFO("Mesos connection timeout [ms]: " + std::to_string(m_mesos_timeout_ms));
	LOG_INFO("Mesos leader following enabled: " + bool_as_text(m_mesos_follow_leader));
	LOG_INFO("Marathon leader following enabled: " + bool_as_text(m_marathon_follow_leader));
	if (!m_mesos_credentials.first.empty())
	{
		LOG_INFO("Mesos credentials provided.");
	}
	if (!m_marathon_credentials.first.empty())
	{
		LOG_INFO("Marathon credentials provided.");
	}
	if (!m_dcos_enterprise_credentials.first.empty())
	{
		LOG_INFO("DC/OS Enterprise credentials provided.");
	}
#endif
	LOG_INFO("coredump enabled: " + bool_as_text(m_enable_coredump));
	LOG_INFO("POSIX queue limit: %lu", m_rlimit_msgqueue);

	if (m_suppressed_comms.size() > 0)
	{
		LOG_INFO("Will ignore all events for the following processes:");
		for (auto& comm : m_suppressed_comms)
		{
			LOG_INFO("  " + comm);
		}
	}
	else
	{
		LOG_INFO("Will not ignore any events by process name");
	}
	if (m_suppressed_types.size() > 0)
	{
		std::string supp_str;
		for (size_t ii = 0; ii < m_suppressed_types.size(); ii++)
		{
			auto val = m_suppressed_types[ii];
			// Ignore exit types because we should
			// always have the corresponding enter
			if (PPME_IS_EXIT(val))
			{
				ASSERT(m_suppressed_types[ii - 1] == val - 1);
				continue;
			}

			supp_str +=
			    std::string(sinsp_utils::event_name_by_id(val)) + "(" + to_string(val) + "), ";
		}
		if (supp_str.size() > 2 && supp_str.compare(supp_str.size() - 2, string::npos, ", ") == 0)
		{
			supp_str.erase(supp_str.size() - 2);
		}
		LOG_WARNING("Will ignore all events for the following types: " + supp_str);
	}
	else
	{
		LOG_INFO("Will not ignore any events by type");
	}

	LOG_INFO("K8s events channel: %s", m_go_k8s_user_events ? "Go" : "legacy");
	if (m_k8s_event_filter)
	{
		LOG_INFO("K8s events filter:" + m_k8s_event_filter->to_string());
	}
	else
	{
		LOG_INFO("K8s events not enabled.");
	}
	if (m_docker_event_filter)
	{
		LOG_INFO("Docker events filter:" + m_docker_event_filter->to_string());
	}
	else
	{
		LOG_INFO("Docker events not enabled.");
	}
	if (m_containerd_event_filter)
	{
		LOG_INFO("ContainerD events filter:" + m_containerd_event_filter->to_string());
	}
	else
	{
		LOG_INFO("ContainerD events not enabled.");
	}
	if (m_auto_config)
	{
		LOG_INFO("Auto config enabled. File types and digests:");
		for (auto& pair : m_supported_auto_configs)
		{
			LOG_INFO("    " + pair.first + ": file digest: " + pair.second->digest());
		}
	}
	else
	{
		LOG_INFO("Auto config disabled");
	}
	if (m_emit_tracers)
	{
		LOG_INFO("Emitting sysdig tracers enabled");
	}

	LOG_INFO("Metric filters and over limit logging:" + bool_as_text(m_excess_metric_log));
	std::ostringstream os;
	if (m_metrics_filter.size())
	{
		for (const auto& e : m_metrics_filter)
		{
			os << std::endl << (e.included() ? "include: " : "exclude: ") << e.to_string();
		}
	}
	LOG_INFO("Metrics filters:" + os.str());
	if (m_excess_metric_log)
	{
		LOG_INFO("Metrics filter log enabled");
	}
	else
	{
		LOG_INFO("Metrics filter log disabled");
	}
	if (m_metrics_cache > 0)
	{
		LOG_INFO("Metrics cache enabled, size: " + std::to_string(m_metrics_cache));
	}
	else
	{
		LOG_INFO("Metrics cache disabled");
	}

	LOG_INFO("snaplen: " + to_string(m_snaplen));
	LOG_INFO("Monitor file frequency: " + std::to_string(m_monitor_files_freq_sec) + " seconds");
	if (!m_monitor_files.empty())
	{
		LOG_INFO("Files to monitor:");
	}
	for (auto const& path : m_monitor_files)
	{
		LOG_INFO("   " + path);
	}

	if (m_query_docker_image_info)
	{
		LOG_INFO("Additional Docker image info fetching enabled.");
	}

	LOG_INFO("Incomplete TCP connection reporting: " +
		 string(m_track_connection_status ? "enabled" : "disabled"));

	if (m_username_lookups)
	{
		LOG_INFO("Username lookups enabled.");
	}

	if (m_track_environment)
	{
		LOG_INFO(
		    "Environment variable reporting enabled, maximum %d envs per flush, %lu bytes per env, "
		    "hash ttl: %lu seconds",
		    m_envs_per_flush,
		    m_max_env_size,
		    m_env_hash_ttl);
		if (m_env_metrics)
		{
			LOG_INFO("Sending environment variables in metrics");
		}
		if (m_env_audit_tap)
		{
			LOG_INFO("Sending environment variables in audit tap");
		}
	}

	if (m_top_files_per_prog)
	{
		LOG_INFO("Reporting top %d files per program.", m_top_files_per_prog);
	}
	if (m_top_files_per_container)
	{
		LOG_INFO("Reporting top %d files per container.", m_top_files_per_container);
	}
	if (m_top_files_per_host)
	{
		LOG_INFO("Reporting top %d files per host.", m_top_files_per_host);
	}

	if (m_top_file_devices_per_prog)
	{
		LOG_INFO("Reporting top %d devices for file I/O per program.", m_top_file_devices_per_prog);
	}
	if (m_top_file_devices_per_container)
	{
		LOG_INFO("Reporting top %d devices for file I/O per container.",
		         m_top_file_devices_per_container);
	}
	if (m_top_file_devices_per_host)
	{
		LOG_INFO("Reporting top %d devices for file I/O per host.", m_top_file_devices_per_host);
	}

	configuration_manager::instance().print_config(log_config);

	// Dump warnings+errors after the main config so they're more visible
	// Always keep these at the bottom
	for (const auto& item : m_config->debugs())
	{
		LOG_DEBUG(item);
	}
	for (const auto& item : m_config->warnings())
	{
		LOG_WARNING(item);
	}
	for (const auto& item : m_config->errors())
	{
		LOG_CRITICAL(item);
	}
}

void dragent_configuration::refresh_aws_metadata()
{
	//
	// AWS EC2 Metadata URL
	//
	const std::string EC2_METADATA_HOST = "169.254.169.254";
	const std::string METADATA_URL_BASE = EC2_METADATA_HOST + "/latest/meta-data";
	const std::string INSTANCE_IDENTITY_URL = EC2_METADATA_HOST + "/latest/dynamic/instance-identity/document";
	std::string err;
	std::string response_buffer;

	err = curl_get(METADATA_URL_BASE + "/public-ipv4", response_buffer);
	if (!err.empty())
	{
		m_aws_metadata.m_public_ipv4 = 0;
		LOG_DEBUG("Unable to fetch AWS metadata. Error while fetching. " + err);
		return;
	}
#ifndef _WIN32
	struct in_addr addr;

	if (inet_aton(response_buffer.c_str(), &addr) == 0)
	{
		m_aws_metadata.m_public_ipv4 = 0;
	}
	else
	{
		m_aws_metadata.m_public_ipv4 = addr.s_addr;
	}
#endif

	response_buffer.clear();
	err = curl_get(METADATA_URL_BASE + "/instance-id", response_buffer);
	if (!err.empty())
	{
		m_aws_metadata.m_instance_id.clear();
		LOG_DEBUG("Unable to fetch AWS metadata. Error while fetching. " + err);
		return;
	}

	m_aws_metadata.m_instance_id = response_buffer;
	if (m_aws_metadata.m_instance_id.find("i-") != 0)
	{
		m_aws_metadata.m_instance_id.clear();
	}

	response_buffer.clear();
	err = curl_get(INSTANCE_IDENTITY_URL, response_buffer);
	if (!err.empty())
	{
		m_aws_metadata.m_account_id.clear();
		m_aws_metadata.m_region.clear();
		LOG_DEBUG("Unable to fetch AWS metadata. Error while fetching. " + err);
		return;
	}

    try 
    {
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response_buffer, root))
        {
            if (!root["accountId"].empty())
            {
                m_aws_metadata.m_account_id = root["accountId"].asString();
            }
            if (!root["region"].empty())
            {
                m_aws_metadata.m_region = root["region"].asString();
            }
        }
        else
        {
            m_aws_metadata.m_account_id.clear();
            m_aws_metadata.m_region.clear();
            LOG_DEBUG("Unable to parse response received from AWS Metdata endpoint: " + response_buffer);
        }
    } catch (Json::Exception& ex) 
    {
        LOG_ERROR("Failed to get account info(accountId/region) from AWS Metadata %s", ex.what());
    }
    catch (...)
    {
        LOG_DEBUG("Unknown exception in getting AWS Metadata");
    }
}

bool dragent_configuration::check_python_version26()
{
	bool ret = false;
	std::string cmd = m_python_binary + " --version -d 2>&1";
	FILE* out = popen(cmd.c_str(), "r");
	if (!out)
	{
		return ret;
	}

	// Sample output:
	// $ python --version -d
	// Python x.x.x+

	// It should only be one line
	char buf[256];
	fgets(buf, sizeof(buf), out);
	pclose(out);
	std::string out_str(buf);
	int pos = out_str.find(" ");
	if (pos == std::string::npos)
	{
		return ret;
	}
	auto version = out_str.substr(pos + 1, out_str.length());
	auto dotPos = version.rfind(".");
	std::string major_version = version.substr(0, dotPos);
	if (!major_version.compare("2.6"))
	{
		ret = true;
	}
	return ret;
}

bool dragent_configuration::get_memory_usage_mb(uint64_t* memory)
{
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) == -1)
	{
		LOG_ERROR(string("getrusage") + strerror(errno));
		return false;
	}
	*memory = usage.ru_maxrss / 1024;
	return true;
}

string dragent_configuration::get_distribution()
{
#ifndef CYGWING_AGENT
	string s;

	try
	{
		Poco::FileInputStream f("/etc/system-release-cpe");
		StreamCopier::copyToString(f, s);
		return s;
	}
	catch (...)
	{
	}

	try
	{
		Poco::FileInputStream f("/etc/lsb-release");
		StreamCopier::copyToString(f, s);
		return s;
	}
	catch (...)
	{
	}

	try
	{
		Poco::FileInputStream f("/etc/debian_version");
		StreamCopier::copyToString(f, s);
		return s;
	}
	catch (...)
	{
	}

	ASSERT(false);
	return s;
#else   // CYGWING_AGENT
	return "Windows - cygwin";
#endif  // CYGWING_AGENT
}

void dragent_configuration::refresh_machine_id()
{
#ifndef CYGWING_AGENT
	m_machine_id = Environment::nodeId();
#else
	//
	// NOTE: Environment::nodeId() is buggy in cygwin poco, and returns
	//       00:00:00:00:00:00. As a workaround we provide our own implementation.
	//
	m_machine_id = windows_helpers::get_machine_uid();
	if (m_machine_id == "")
	{
		throw sinsp_exception("cannot gather machine ID");
	}
#endif
}

bool dragent_configuration::is_executable(const string& path)
{
	File file(path);
	return file.exists() && file.canExecute();
}

int dragent_configuration::save_auto_config(const string& config_filename,
                                            const string& config_data,
                                            string& errstr)
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

void dragent_configuration::set_auto_config_directory(const string& config_directory)
{
	for (auto& it : m_supported_auto_configs)
	{
		it.second->set_config_directory(config_directory);
	}
}

std::string dragent_configuration::get_aws_instance_id()
{
	return m_aws_metadata.m_instance_id;
}

std::string dragent_configuration::get_aws_account_id()
{
	return m_aws_metadata.m_account_id;
}

std::string dragent_configuration::get_aws_region()
{
	return m_aws_metadata.m_region;
}
