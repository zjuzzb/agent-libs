#include "analyzer_int.h"
#include "common_logger.h"
#include "proc_filter.h"
#include "sinsp.h"
#include "sinsp_int.h"

namespace
{
COMMON_LOGGER();
}

using namespace std;

sinsp_configuration::sinsp_configuration()
    : m_tracepoint_hits_threshold(N_TRACEPOINT_HITS_THRESHOLD, SWITCHER_NSECONDS),
      m_cpu_max_sr_threshold(CPU_MAX_SR_THRESHOLD, SWITCHER_NSECONDS)
{
	m_machine_id = "<NA>";
	m_customer_id = "<NA>";
	m_protocols_truncation_size = 512;
	m_mounts_limit_size = 15u;
#ifndef CYGWING_AGENT
	m_mesos_autodetect = true;
#endif
	m_jmx_limit = 500;
	m_executed_commands_capture_enabled = false;
	m_command_lines_capture_mode = command_capture_mode_t::CM_TTY;
	m_command_lines_include_container_healthchecks = false;
	m_capture_dragent_events = false;
	m_detect_stress_tools = false;
}

const string& sinsp_configuration::get_machine_id() const
{
	return m_machine_id;
}

void sinsp_configuration::set_machine_id(string machine_id)
{
	m_machine_id = machine_id;
}

const string& sinsp_configuration::get_customer_id() const
{
	return m_customer_id;
}

void sinsp_configuration::set_customer_id(string customer_id)
{
	m_customer_id = customer_id;
}

bool sinsp_configuration::get_executed_commands_capture_enabled() const
{
	return m_executed_commands_capture_enabled;
}

void sinsp_configuration::set_executed_commands_capture_enabled(bool enabled)
{
	m_executed_commands_capture_enabled = enabled;
}

sinsp_configuration::command_capture_mode_t sinsp_configuration::get_command_lines_capture_mode()
    const
{
	return m_command_lines_capture_mode;
}

void sinsp_configuration::set_command_lines_capture_mode(command_capture_mode_t capture_mode)
{
	m_command_lines_capture_mode = capture_mode;
}

void sinsp_configuration::set_command_lines_include_container_healthchecks(bool enabled)
{
	m_command_lines_include_container_healthchecks = enabled;
}

bool sinsp_configuration::get_command_lines_include_container_healthchecks() const
{
	return m_command_lines_include_container_healthchecks;
}

set<string> sinsp_configuration::get_command_lines_valid_ancestors() const
{
	return m_command_lines_valid_ancestors;
}

void sinsp_configuration::set_command_lines_valid_ancestors(const set<string>& valid_ancestors)
{
	m_command_lines_valid_ancestors = valid_ancestors;
}

bool sinsp_configuration::is_command_lines_valid_ancestor(const string& ancestor) const
{
	return m_command_lines_valid_ancestors.find(ancestor) != m_command_lines_valid_ancestors.end();
}

bool sinsp_configuration::get_capture_dragent_events() const
{
	return m_capture_dragent_events;
}

void sinsp_configuration::set_capture_dragent_events(bool enabled)
{
	m_capture_dragent_events = enabled;
}

void sinsp_configuration::set_version(const string& version)
{
	m_version = version;
}

const std::string& sinsp_configuration::get_version(void) const
{
	return m_version;
}

const string& sinsp_configuration::get_instance_id() const
{
	return m_instance_id;
}

void sinsp_configuration::set_instance_id(const string& instance_id)
{
	m_instance_id = instance_id;
}

const string& sinsp_configuration::get_account_id() const
{
	return m_account_id;
}

void sinsp_configuration::set_account_id(const string& account_id)
{
	m_account_id = account_id;
}

const string& sinsp_configuration::get_region() const
{
	return m_region;
}

void sinsp_configuration::set_region(const string& region)
{
	m_region = region;
}

#ifndef CYGWING_AGENT
void sinsp_configuration::set_k8s_delegated_nodes(int k8s_delegated_nodes)
{
	m_k8s_delegated_nodes = k8s_delegated_nodes;
}

int sinsp_configuration::get_k8s_delegated_nodes() const
{
	return m_k8s_delegated_nodes;
}

void sinsp_configuration::set_k8s_extensions(const std::set<std::string>& k8s_extensions)
{
	m_k8s_extensions = k8s_extensions;
}

const std::set<std::string>& sinsp_configuration::get_k8s_extensions() const
{
	return m_k8s_extensions;
}

void sinsp_configuration::set_k8s_cluster_name(const std::string& k8s_cluster_name)
{
	m_k8s_cluster_name = k8s_cluster_name;
}

const std::string& sinsp_configuration::get_k8s_cluster_name() const
{
	return m_k8s_cluster_name;
}

string sinsp_configuration::get_mesos_uri(const std::string& sought_url) const
{
	if (sought_url.empty())
	{
		return sought_url;
	}
	uri url(sought_url);
	if (!m_mesos_credentials.first.empty())
	{
		url.set_credentials(m_mesos_credentials);
	}
	return url.to_string(true);
}

void sinsp_configuration::set_mesos_uri(string& url, const string& new_url)
{
	if (!new_url.empty())
	{
		try
		{
			uri u(new_url);
			u.set_path("");
			url = u.to_string(true);
		}
		catch (sinsp_exception& ex)
		{
			g_logger.log(std::string("Error setting Mesos URI: ").append(ex.what()),
			             sinsp_logger::SEV_ERROR);
		}
		return;
	}
	url.clear();
}

string sinsp_configuration::get_mesos_state_uri() const
{
	return get_mesos_uri(m_mesos_state_uri);
}

void sinsp_configuration::set_mesos_state_uri(const string& url)
{
	set_mesos_uri(m_mesos_state_uri, url);
}

string sinsp_configuration::get_mesos_state_original_uri() const
{
	return get_mesos_uri(m_mesos_state_original_uri);
}

void sinsp_configuration::set_mesos_state_original_uri(const string& url)
{
	set_mesos_uri(m_mesos_state_original_uri, url);
}

const vector<string>& sinsp_configuration::get_marathon_uris() const
{
	if (!m_marathon_uris.empty())
	{
		for (vector<string>::iterator it = m_marathon_uris.begin(); it != m_marathon_uris.end();
		     ++it)
		{
			if (!it->empty())
			{
				uri url(*it);
				if (!m_marathon_credentials.first.empty())
				{
					url.set_credentials(m_marathon_credentials);
				}
				*it = url.to_string(true);
			}
		}
	}
	return m_marathon_uris;
}

void sinsp_configuration::set_marathon_uris(const vector<string>& uris)
{
	for (const auto& u : uris)
	{
		if (!u.empty())
		{
			uri::check(u);
		}
	}
	m_marathon_uris = uris;
}

bool sinsp_configuration::get_mesos_autodetect_enabled() const
{
	return m_mesos_autodetect;
}

void sinsp_configuration::set_mesos_autodetect_enabled(bool enabled)
{
	m_mesos_autodetect = enabled;
}

void sinsp_configuration::set_mesos_timeout_ms(int mesos_timeout_ms)
{
	m_mesos_timeout_ms = mesos_timeout_ms;
}

int sinsp_configuration::get_mesos_timeout_ms() const
{
	return m_mesos_timeout_ms;
}

bool sinsp_configuration::get_mesos_follow_leader() const
{
	return m_mesos_follow_leader;
}

void sinsp_configuration::set_mesos_follow_leader(bool enabled)
{
	m_mesos_follow_leader = enabled;
}

bool sinsp_configuration::get_marathon_follow_leader() const
{
	return m_marathon_follow_leader;
}

void sinsp_configuration::set_marathon_follow_leader(bool enabled)
{
	m_marathon_follow_leader = enabled;
}

const mesos::credentials_t& sinsp_configuration::get_mesos_credentials() const
{
	return m_mesos_credentials;
}

void sinsp_configuration::set_mesos_credentials(const mesos::credentials_t& creds)
{
	m_mesos_credentials.first = creds.first;
	m_mesos_credentials.second = creds.second;
}

const mesos::credentials_t& sinsp_configuration::get_marathon_credentials() const
{
	return m_marathon_credentials;
}

void sinsp_configuration::set_marathon_credentials(const mesos::credentials_t& creds)
{
	m_marathon_credentials.first = creds.first;
	m_marathon_credentials.second = creds.second;
}

const mesos::credentials_t& sinsp_configuration::get_dcos_enterprise_credentials() const
{
	return m_dcos_enterprise_credentials;
}

void sinsp_configuration::set_dcos_enterprise_credentials(const mesos::credentials_t& creds)
{
	m_dcos_enterprise_credentials = creds;
}

void sinsp_configuration::set_marathon_skip_labels(const std::set<std::string>& labels)
{
	m_marathon_skip_labels = labels;
}

const std::set<std::string>& sinsp_configuration::get_marathon_skip_labels() const
{
	return m_marathon_skip_labels;
}
#endif  // CYGWING_AGENT

bool sinsp_configuration::get_curl_debug() const
{
	return m_curl_debug;
}

void sinsp_configuration::set_curl_debug(bool enabled)
{
	m_curl_debug = enabled;
}

uint32_t sinsp_configuration::get_protocols_truncation_size() const
{
	return m_protocols_truncation_size;
}

void sinsp_configuration::set_protocols_truncation_size(uint32_t truncation_size)
{
	m_protocols_truncation_size = truncation_size;
}

user_event_filter_t::ptr_t sinsp_configuration::get_k8s_event_filter() const
{
	return m_k8s_event_filter;
}

void sinsp_configuration::set_k8s_event_filter(user_event_filter_t::ptr_t event_filter)
{
	m_k8s_event_filter = event_filter;
}

user_event_filter_t::ptr_t sinsp_configuration::get_docker_event_filter() const
{
	return m_docker_event_filter;
}

void sinsp_configuration::set_docker_event_filter(user_event_filter_t::ptr_t event_filter)
{
	m_docker_event_filter = event_filter;
}

user_event_filter_t::ptr_t sinsp_configuration::get_containerd_event_filter() const
{
	return m_containerd_event_filter;
}

void sinsp_configuration::set_containerd_event_filter(user_event_filter_t::ptr_t event_filter)
{
	m_containerd_event_filter = event_filter;
}

filter_vec_t sinsp_configuration::get_mounts_filter() const
{
	return m_mounts_filter;
}

void sinsp_configuration::set_mounts_filter(const filter_vec_t& mounts_filter)
{
	m_mounts_filter = mounts_filter;
}

unsigned sinsp_configuration::get_mounts_limit_size() const
{
	return m_mounts_limit_size;
}

void sinsp_configuration::set_mounts_limit_size(unsigned mounts_limit_size)
{
	m_mounts_limit_size = mounts_limit_size;
}

const std::set<double>& sinsp_configuration::get_percentiles() const
{
	return m_percentiles;
}

shared_ptr<proc_filter::group_pctl_conf> sinsp_configuration::get_group_pctl_conf() const
{
	return m_group_pctl_conf;
}

void sinsp_configuration::set_percentiles(const std::set<double>& percentiles,
                                          shared_ptr<proc_filter::group_pctl_conf> group_pctl_conf)
{
	m_percentiles = percentiles;
	m_group_pctl_conf = group_pctl_conf;
}

shared_ptr<proc_filter::conf> sinsp_configuration::get_container_filter() const
{
	return m_container_filter;
}

void sinsp_configuration::set_container_filter(shared_ptr<proc_filter::conf> conf)
{
	m_container_filter = conf;
}

void sinsp_configuration::set_go_k8s_user_events(bool enabled)
{
	m_go_k8s_user_events = enabled;
}

bool sinsp_configuration::get_go_k8s_user_events() const
{
	return m_go_k8s_user_events;
}

void sinsp_configuration::set_log_dir(const string& dir)
{
	m_log_dir = dir;
}

string& sinsp_configuration::get_log_dir()
{
	return m_log_dir;
}

bool sinsp_configuration::get_detect_stress_tools() const
{
	return m_detect_stress_tools;
}

void sinsp_configuration::set_detect_stress_tools(bool val)
{
	m_detect_stress_tools = val;
}

const pair<long, unsigned>& sinsp_configuration::get_tracepoint_hits_threshold() const
{
	return m_tracepoint_hits_threshold;
}

void sinsp_configuration::set_tracepoint_hits_threshold(long threshold, unsigned ntimes)
{
	m_tracepoint_hits_threshold = make_pair(threshold, ntimes);
}

const pair<double, unsigned>& sinsp_configuration::get_cpu_max_sr_threshold() const
{
	return m_cpu_max_sr_threshold;
}

void sinsp_configuration::set_cpu_max_sr_threshold(double threshold, unsigned ntimes)
{
	m_cpu_max_sr_threshold = make_pair(threshold, ntimes);
}

void sinsp_configuration::set_procfs_scan_procs(const set<string>& procs)
{
	m_procfs_scan_procs = procs;
	for (const auto& proc : m_procfs_scan_procs)
	{
		LOG_INFO("procfs_scan_proc: %s", proc.c_str());
	}
}

const set<string>& sinsp_configuration::get_procfs_scan_procs()
{
       return m_procfs_scan_procs;
}

