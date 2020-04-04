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
      m_cpu_max_sr_threshold(CPU_MAX_SR_THRESHOLD, SWITCHER_NSECONDS),
      m_procfs_scan_interval_ms(0),
      m_procfs_scan_mem_interval_ms(0)
{
	m_machine_id = "<NA>";
	m_customer_id = "<NA>";
	m_max_connections_in_proto = DEFAULT_MAX_CONNECTIONS_IN_PROTO;
	m_aggregate_connections_in_proto = AGGREGATE_CONNECTIONS_IN_PROTO;
	m_host_hidden = false;
	m_protocols_truncation_size = 512;
	m_mounts_limit_size = 15u;
#ifndef CYGWING_AGENT
	m_mesos_autodetect = true;
#endif
	m_jmx_limit = 500;
	m_app_checks_always_send = false;
	m_memdump_size = 0;
	m_executed_commands_capture_enabled = false;
	m_command_lines_capture_mode = command_capture_mode_t::CM_TTY;
	m_command_lines_include_container_healthchecks = false;
	m_capture_dragent_events = false;
	m_detect_stress_tools = false;
	m_swarm_enabled = true;
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

uint32_t sinsp_configuration::get_max_connections_in_proto() const
{
	return m_max_connections_in_proto;
}

void sinsp_configuration::set_max_connections_in_proto(uint32_t max_connections_in_proto)
{
	m_max_connections_in_proto = max_connections_in_proto;
}

bool sinsp_configuration::get_aggregate_connections_in_proto() const
{
	return m_aggregate_connections_in_proto;
}

void sinsp_configuration::set_aggregate_connections_in_proto(bool aggregate)
{
	m_aggregate_connections_in_proto = aggregate;
}

uint64_t sinsp_configuration::get_falco_baselining_report_interval_ns() const
{
	return m_falco_baselining_report_interval_ns;
}

void sinsp_configuration::set_falco_baselining_report_interval_ns(uint64_t report_interval)
{
	m_falco_baselining_report_interval_ns = report_interval;
}

uint64_t sinsp_configuration::get_falco_baselining_autodisable_interval_ns() const
{
	return m_falco_baselining_autodisable_interval_ns;
}

void sinsp_configuration::set_falco_baselining_autodisable_interval_ns(
    uint64_t autodisable_interval)
{
	m_falco_baselining_autodisable_interval_ns = autodisable_interval;
}

float sinsp_configuration::get_falco_baselining_max_drops_buffer_rate_percentage() const
{
	return m_falco_baselining_max_drops_buffer_rate_percentage;
}

void sinsp_configuration::set_falco_baselining_max_drops_buffer_rate_percentage(
    float max_drops_buffer_rate_percentage)
{
	m_falco_baselining_max_drops_buffer_rate_percentage = max_drops_buffer_rate_percentage;
}

uint32_t sinsp_configuration::get_falco_baselining_max_sampling_ratio() const
{
	return m_falco_baselining_max_sampling_ratio;
}

void sinsp_configuration::set_falco_baselining_max_sampling_ratio(uint32_t max_sampling_ratio)
{
	m_falco_baselining_max_sampling_ratio = max_sampling_ratio;
}

bool sinsp_configuration::get_falco_baselining_randomize_start() const
{
	return m_falco_baselining_randomize_start;
}

void sinsp_configuration::set_falco_baselining_randomize_start(bool enabled)
{
	m_falco_baselining_randomize_start = enabled;
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

uint64_t sinsp_configuration::get_memdump_size() const
{
	return m_memdump_size;
}

void sinsp_configuration::set_memdump_size(uint64_t size)
{
	m_memdump_size = size;
}

const string& sinsp_configuration::get_host_custom_name() const
{
	return m_host_custom_name;
}

void sinsp_configuration::set_host_custom_name(string host_custom_name)
{
	m_host_custom_name = host_custom_name;
}

const string& sinsp_configuration::get_host_tags() const
{
	return m_host_tags;
}

void sinsp_configuration::set_host_tags(const string& host_tags)
{
	m_host_tags = host_tags;
}

bool sinsp_configuration::get_host_hidden() const
{
	return m_host_hidden;
}

void sinsp_configuration::set_host_hidden(bool host_hidden)
{
	m_host_hidden = host_hidden;
}

const string& sinsp_configuration::get_hidden_processes() const
{
	return m_hidden_processes;
}

void sinsp_configuration::set_hidden_processes(string hidden_processes)
{
	m_hidden_processes = hidden_processes;
}

const string& sinsp_configuration::get_host_custom_map() const
{
	return m_host_custom_map;
}

void sinsp_configuration::set_host_custom_map(string host_custom_map)
{
	m_host_custom_map = host_custom_map;
}

const string& sinsp_configuration::get_version() const
{
	return m_version;
}

void sinsp_configuration::set_version(const string& version)
{
	m_version = version;
}

const string& sinsp_configuration::get_instance_id() const
{
	return m_instance_id;
}

void sinsp_configuration::set_instance_id(const string& instance_id)
{
	m_instance_id = instance_id;
}

void sinsp_configuration::set_known_ports(const ports_set& v)
{
	m_known_ports = v;
}

const ports_set& sinsp_configuration::get_known_ports() const
{
	return m_known_ports;
}

void sinsp_configuration::set_blacklisted_ports(const vector<uint16_t>& ports)
{
	for (auto port : ports)
	{
		m_blacklisted_ports.set(port);
	}
}

void sinsp_configuration::set_blacklisted_ports(const ports_set& v)
{
	m_blacklisted_ports = v;
}

const ports_set& sinsp_configuration::get_blacklisted_ports() const
{
	return m_blacklisted_ports;
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

void sinsp_configuration::set_smart_container_reporting(bool enabled)
{
	m_smart_container_reporting = enabled;
}

bool sinsp_configuration::get_smart_container_reporting() const
{
	return m_smart_container_reporting;
}

void sinsp_configuration::set_go_k8s_user_events(bool enabled)
{
	m_go_k8s_user_events = enabled;
}

bool sinsp_configuration::get_go_k8s_user_events() const
{
	return m_go_k8s_user_events;
}

void sinsp_configuration::set_add_event_scopes(bool enabled)
{
	m_add_event_scopes = enabled;
}

bool sinsp_configuration::get_add_event_scopes() const
{
	return m_add_event_scopes;
}

void sinsp_configuration::set_statsite_check_format(bool enabled)
{
	m_statsite_check_format = enabled;
}

bool sinsp_configuration::get_statsite_check_format() const
{
	return m_statsite_check_format;
}

void sinsp_configuration::set_log_dir(const string& dir)
{
	m_log_dir = dir;
}

string& sinsp_configuration::get_log_dir()
{
	return m_log_dir;
}

bool sinsp_configuration::get_app_checks_always_send() const
{
	return m_app_checks_always_send;
}

void sinsp_configuration::set_app_checks_always_send(bool value)
{
	m_app_checks_always_send = value;
}

bool sinsp_configuration::get_detect_stress_tools() const
{
	return m_detect_stress_tools;
}

void sinsp_configuration::set_detect_stress_tools(bool val)
{
	m_detect_stress_tools = val;
}

bool sinsp_configuration::get_swarm_enabled() const
{
	return m_swarm_enabled;
}

void sinsp_configuration::set_swarm_enabled(bool val)
{
	m_swarm_enabled = val;
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

void sinsp_configuration::set_procfs_scan_delay_ms(uint32_t scan_delay_ms)
{
	m_procfs_scan_delay_ms = scan_delay_ms;
}

uint32_t sinsp_configuration::get_procfs_scan_delay_ms() const
{
	return m_procfs_scan_delay_ms;
}

void sinsp_configuration::set_procfs_scan_interval_ms(uint32_t scan_interval_ms)
{
	m_procfs_scan_interval_ms = scan_interval_ms;
}

uint32_t sinsp_configuration::get_procfs_scan_interval_ms() const
{
	return m_procfs_scan_interval_ms;
}

void sinsp_configuration::set_procfs_scan_mem_interval_ms(uint32_t scan_interval_ms)
{
	m_procfs_scan_mem_interval_ms = scan_interval_ms;
}

uint32_t sinsp_configuration::get_procfs_scan_mem_interval_ms() const
{
	return m_procfs_scan_mem_interval_ms;
}

void sinsp_configuration::set_procfs_scan_procs(const set<string>& procs, uint32_t interval)
{
	m_procfs_scan_procs = procs;
	m_procfs_scan_interval = interval;
	for (const auto& proc : m_procfs_scan_procs)
	{
		LOG_INFO("procfs_scan_proc: %s", proc.c_str());
	}
	LOG_INFO("procfs_scan_interval: %d", m_procfs_scan_interval);
}
const set<string>& sinsp_configuration::get_procfs_scan_procs()
{
	return m_procfs_scan_procs;
}
uint32_t sinsp_configuration::get_procfs_scan_interval()
{
	return m_procfs_scan_interval;
}
