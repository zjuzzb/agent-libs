#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"

#ifdef HAS_ANALYZER

sinsp_configuration::sinsp_configuration():
	m_tracepoint_hits_threshold(N_TRACEPOINT_HITS_THRESHOLD, SWITCHER_NSECONDS),
	m_cpu_max_sr_threshold(CPU_MAX_SR_THRESHOLD, SWITCHER_NSECONDS)
{
	set_connection_timeout_in_sec(DEFAULT_CONNECTION_TIMEOUT_SEC);
	m_connection_pruning_interval_ns = 30 * ONE_SECOND_IN_NS;
	set_emit_metrics_to_file(false);
	set_compress_metrics(false);
	m_machine_id = "<NA>";
	m_customer_id = "<NA>";
	m_analyzer_sample_len_ns = ANALYZER_DEFAULT_SAMPLE_LENGTH_NS;
	m_analyzer_original_sample_len_ns = ANALYZER_DEFAULT_SAMPLE_LENGTH_NS;
	m_metrics_directory = string(".") + DIR_PATH_SEPARATOR;
	m_max_connection_table_size = MAX_CONNECTION_TABLE_SIZE;
	m_max_connections_in_proto = DEFAULT_MAX_CONNECTIONS_IN_PROTO;
	m_aggregate_connections_in_proto = AGGREGATE_CONNECTIONS_IN_PROTO;
	m_autodrop_enabled = AUTODROP_ENABLED;
	m_drop_upper_threshold = DROP_UPPER_THRESHOLD;
	m_drop_lower_threshold = DROP_LOWER_THRESHOLD;
	m_drop_threshold_consecutive_seconds = DROP_THRESHOLD_CONSECUTIVE_SECONDS;
	m_host_hidden = false;
	m_k8s_autodetect = true;
	m_protocols_truncation_size = 512;
	m_mesos_autodetect = true;
	m_jmx_limit = 500;
	m_app_checks_limit = 300;
	m_memdump_size = 0;
	m_falco_baselining_enabled = FALCO_BASELINING_ENABLED;
	m_command_lines_capture_enabled = false;
	m_command_lines_capture_mode = command_capture_mode_t::CM_TTY;
	m_capture_dragent_events = false;
	m_detect_stress_tools = false;
	m_security_enabled = false;
	m_cointerface_enabled = true;
	m_swarm_enabled = true;
}

sinsp_configuration::sinsp_configuration(const sinsp_configuration& configuration)
{
	m_connection_timeout_ns = configuration.m_connection_timeout_ns;
}

uint64_t sinsp_configuration::get_connection_timeout_ns() const
{
	return m_connection_timeout_ns;
}

uint64_t sinsp_configuration::get_connection_timeout_sec() const
{
	return m_connection_timeout_ns / ONE_SECOND_IN_NS;
}

void sinsp_configuration::set_connection_timeout_in_sec(uint64_t timeout_sec)
{
	m_connection_timeout_ns = timeout_sec * ONE_SECOND_IN_NS;
}

uint64_t sinsp_configuration::get_connection_pruning_interval_ns() const
{
	return m_connection_pruning_interval_ns;
}

void sinsp_configuration::set_connection_pruning_interval_ns(uint64_t interval_ns)
{
	m_connection_pruning_interval_ns = interval_ns;
}

bool sinsp_configuration::get_emit_metrics_to_file() const
{
	return m_emit_metrics_to_file;
}

void sinsp_configuration::set_emit_metrics_to_file(bool emit)
{
	m_emit_metrics_to_file = emit;
}

bool sinsp_configuration::get_compress_metrics() const
{
	return m_compress_metrics;
}

void sinsp_configuration::set_compress_metrics(bool emit)
{
	m_compress_metrics = emit;
}

const string& sinsp_configuration::get_metrics_directory() const
{
	return m_metrics_directory;
}

void sinsp_configuration::set_metrics_directory(string metrics_directory)
{
	m_metrics_directory = metrics_directory;
	if(m_metrics_directory[m_metrics_directory.size() - 1] != DIR_PATH_SEPARATOR)
	{
		m_metrics_directory += DIR_PATH_SEPARATOR;
	}
}

sinsp_logger::output_type sinsp_configuration::get_log_output_type() const
{
	//
	// XXX not implemented yet
	//
	ASSERT(false);
	return sinsp_logger::OT_NONE;
}

void sinsp_configuration::set_log_output_type(sinsp_logger::output_type log_output_type)
{
	g_logger.set_log_output_type(log_output_type);
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

uint64_t sinsp_configuration::get_analyzer_sample_len_ns() const
{
	return m_analyzer_sample_len_ns;
}

uint64_t sinsp_configuration::get_analyzer_original_sample_len_ns() const
{
	return m_analyzer_original_sample_len_ns;
}

void sinsp_configuration::set_analyzer_sample_len_ns(uint64_t analyzer_sample_length_ns)
{
	m_analyzer_sample_len_ns = analyzer_sample_length_ns;
}

uint32_t sinsp_configuration::get_max_connection_table_size() const
{
	return m_max_connection_table_size;
}

void sinsp_configuration::set_max_connection_table_size(uint32_t max_connection_table_size)
{
	m_max_connection_table_size = max_connection_table_size;
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

bool sinsp_configuration::get_autodrop_enabled() const
{
	return m_autodrop_enabled;
}

void sinsp_configuration::set_autodrop_enabled(bool enabled)
{
	if(enabled)
	{
		m_autodrop_enabled = true;
	}
	else
	{
		m_autodrop_enabled = false;	
	}
}

bool sinsp_configuration::get_falco_baselining_enabled() const
{
	return m_falco_baselining_enabled;
}

void sinsp_configuration::set_falco_baselining_enabled(bool enabled)
{
	m_falco_baselining_enabled = enabled;
}

bool sinsp_configuration::get_command_lines_capture_enabled() const
{
	return m_command_lines_capture_enabled;
}

void sinsp_configuration::set_command_lines_capture_enabled(bool enabled)
{
	m_command_lines_capture_enabled = enabled;
}

sinsp_configuration::command_capture_mode_t sinsp_configuration::get_command_lines_capture_mode() const
{
	return m_command_lines_capture_mode;
}

void sinsp_configuration::set_command_lines_capture_mode(command_capture_mode_t capture_mode)
{
	m_command_lines_capture_mode = capture_mode;
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

uint32_t sinsp_configuration::get_drop_upper_threshold(uint32_t nprocs) const
{
	if(nprocs > 0)
	{
		return MIN(m_drop_upper_threshold + (nprocs - 1), 100);
	}
	else
	{
		return m_drop_upper_threshold;
		ASSERT(false);
	}
}

void sinsp_configuration::set_drop_upper_threshold(uint32_t drop_upper_threshold)
{
	m_drop_upper_threshold = drop_upper_threshold;
}

uint32_t sinsp_configuration::get_drop_lower_threshold(uint32_t nprocs) const
{
	//return 3;
	if(nprocs > 0)
	{
		return MIN(m_drop_lower_threshold + (nprocs - 1) * 4 / 5, 90);
	}
	else
	{
		return m_drop_lower_threshold;
		ASSERT(false);
	}
}

void sinsp_configuration::set_drop_lower_threshold(uint32_t drop_lower_threshold)
{
	m_drop_lower_threshold = drop_lower_threshold;
}

uint32_t sinsp_configuration::get_drop_threshold_consecutive_seconds() const
{
	return m_drop_threshold_consecutive_seconds;
}

void sinsp_configuration::set_drop_threshold_consecutive_seconds(uint32_t drop_threshold_consecutive_seconds)
{
	m_drop_threshold_consecutive_seconds = drop_threshold_consecutive_seconds;
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

const bool sinsp_configuration::get_host_hidden() const
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

void sinsp_configuration::set_known_ports(const ports_set &v)
{
	m_known_ports = v;
}

const ports_set & sinsp_configuration::get_known_ports() const
{
	return m_known_ports;
}

void sinsp_configuration::set_blacklisted_ports(const vector<uint16_t> &ports)
{
	for(auto port : ports)
	{
		m_blacklisted_ports.set(port);
	}
}

void sinsp_configuration::set_blacklisted_ports(const ports_set &v)
{
	m_blacklisted_ports = v;
}

const ports_set & sinsp_configuration::get_blacklisted_ports() const
{
	return m_blacklisted_ports;
}

void sinsp_configuration::set_k8s_api_server(const string& k8s_api)
{
	m_k8s_api = k8s_api;
}

const string & sinsp_configuration::get_k8s_api_server() const
{
	return m_k8s_api;
}

bool sinsp_configuration::get_k8s_autodetect_enabled() const
{
	return m_k8s_autodetect;
}

void sinsp_configuration::set_k8s_autodetect_enabled(bool enabled)
{
	m_k8s_autodetect = enabled;
}

void sinsp_configuration::set_k8s_ssl_cert_type(const string& k8s_ssl_cert_type)
{
	m_k8s_ssl_cert_type = k8s_ssl_cert_type;
}

const string & sinsp_configuration::get_k8s_ssl_cert_type() const
{
	return m_k8s_ssl_cert_type;
}

void sinsp_configuration::set_k8s_ssl_cert(const string& k8s_ssl_cert)
{
	m_k8s_ssl_cert = k8s_ssl_cert;
}

const string & sinsp_configuration::get_k8s_ssl_cert() const
{
	return m_k8s_ssl_cert;
}

void sinsp_configuration::set_k8s_ssl_key(const string& k8s_ssl_key)
{
	m_k8s_ssl_key = k8s_ssl_key;
}

const string & sinsp_configuration::get_k8s_ssl_key() const
{
	return m_k8s_ssl_key;
}

void sinsp_configuration::set_k8s_ssl_key_password(const string& k8s_ssl_key_password)
{
	m_k8s_ssl_key_password = k8s_ssl_key_password;
}

const string & sinsp_configuration::get_k8s_ssl_key_password() const
{
	return m_k8s_ssl_key_password;
}

void sinsp_configuration::set_k8s_ssl_ca_certificate(const string& k8s_ssl_ca_cert)
{
	m_k8s_ssl_ca_certificate = k8s_ssl_ca_cert;
}

const string & sinsp_configuration::get_k8s_ssl_ca_certificate() const
{
	return m_k8s_ssl_ca_certificate;
}

void sinsp_configuration::set_k8s_ssl_verify_certificate(bool k8s_ssl_verify_cert)
{
	m_k8s_ssl_verify_certificate = k8s_ssl_verify_cert;
}

bool sinsp_configuration::get_k8s_ssl_verify_certificate() const
{
	return m_k8s_ssl_verify_certificate;
}

void sinsp_configuration::set_k8s_timeout_s(uint64_t k8s_timeout_s)
{
	m_k8s_timeout_s = k8s_timeout_s;
}

uint64_t sinsp_configuration::get_k8s_timeout_s() const
{
	return m_k8s_timeout_s;
}

void sinsp_configuration::set_k8s_delegated_nodes(int k8s_delegated_nodes)
{
	m_k8s_delegated_nodes = k8s_delegated_nodes;
}

int sinsp_configuration::get_k8s_delegated_nodes() const
{
	return m_k8s_delegated_nodes;
}

void sinsp_configuration::set_k8s_simulate_delegation(bool k8s_simulate_delegation)
{
	m_k8s_simulate_delegation = k8s_simulate_delegation;
}

bool sinsp_configuration::get_k8s_simulate_delegation() const
{
	return m_k8s_simulate_delegation;
}

void sinsp_configuration::set_k8s_bt_auth_token(const string& k8s_bt_auth_token)
{
	m_k8s_bt_auth_token = k8s_bt_auth_token;
}

const string & sinsp_configuration::get_k8s_bt_auth_token() const
{
	return m_k8s_bt_auth_token;
}

void sinsp_configuration::set_k8s_extensions(const std::set<std::string>& k8s_extensions)
{
	m_k8s_extensions = k8s_extensions;
}

const std::set<std::string>& sinsp_configuration::get_k8s_extensions() const
{
	return m_k8s_extensions;
}

void sinsp_configuration::set_k8s_cluster_name(const std::string &k8s_cluster_name)
{
	m_k8s_cluster_name = k8s_cluster_name;
}

const std::string& sinsp_configuration::get_k8s_cluster_name() const
{
	return m_k8s_cluster_name;
}

unsigned sinsp_configuration::get_statsd_limit() const
{
	return m_statsd_limit;
}

void sinsp_configuration::set_statsd_limit(unsigned value)
{
	m_statsd_limit = min(value, STATSD_METRIC_HARD_LIMIT);
}

string sinsp_configuration::get_mesos_uri(const std::string& sought_url) const
{
	if(sought_url.empty())
	{
		return sought_url;
	}
	uri url(sought_url);
	if(!m_mesos_credentials.first.empty())
	{
		url.set_credentials(m_mesos_credentials);
	}
	return url.to_string(true);
}

void sinsp_configuration::set_mesos_uri(string& url, const string & new_url)
{
	if(!new_url.empty())
	{
		try
		{
			uri u(new_url);
			u.set_path("");
			url = u.to_string(true);
		}
		catch(sinsp_exception& ex)
		{
			g_logger.log(std::string("Error setting Mesos URI: ").append(ex.what()), sinsp_logger::SEV_ERROR);
		}
		return;
	}
	url.clear();
}

string sinsp_configuration::get_mesos_state_uri() const
{
	return get_mesos_uri(m_mesos_state_uri);
}

void sinsp_configuration::set_mesos_state_uri(const string & url)
{
	set_mesos_uri(m_mesos_state_uri, url);
}

string sinsp_configuration::get_mesos_state_original_uri() const
{
	return get_mesos_uri(m_mesos_state_original_uri);
}

void sinsp_configuration::set_mesos_state_original_uri(const string & url)
{
	set_mesos_uri(m_mesos_state_original_uri, url);
}

const vector<string>& sinsp_configuration::get_marathon_uris() const
{
	if(!m_marathon_uris.empty())
	{
		for(vector<string>::iterator it = m_marathon_uris.begin(); it != m_marathon_uris.end(); ++it)
		{
			if(!it->empty())
			{
				uri url(*it);
				if(!m_marathon_credentials.first.empty())
				{
					url.set_credentials(m_marathon_credentials);
				}
				*it = url.to_string(true);
			}
		}
	}
	return m_marathon_uris;
}

void sinsp_configuration::set_marathon_uris(const vector<string> & uris)
{
	for(const auto& u : uris)
	{
		if(!u.empty())
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

void sinsp_configuration::set_marathon_skip_labels(std::set<std::string> &labels)
{
	m_marathon_skip_labels = labels;
}

const std::set<std::string> & sinsp_configuration::get_marathon_skip_labels() const
{
	return m_marathon_skip_labels;
}

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

metrics_filter_vec sinsp_configuration::get_metrics_filter() const
{
	return m_metrics_filter;
}

void sinsp_configuration::set_metrics_filter(const metrics_filter_vec& metrics_filter)
{
	m_metrics_filter = metrics_filter;
}

metrics_filter_vec sinsp_configuration::get_mounts_filter() const
{
	return m_mounts_filter;
}

void sinsp_configuration::set_mounts_filter(const mount_points_filter_vec& mounts_filter)
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

bool sinsp_configuration::get_excess_metrics_log() const
{
	return m_excess_metrics_log;
}

void sinsp_configuration::set_excess_metrics_log(bool log)
{
	m_excess_metrics_log = log;
}

unsigned sinsp_configuration::get_metrics_cache() const
{
	return m_metrics_cache;
}

void sinsp_configuration::set_metrics_cache(unsigned sz)
{
	m_metrics_cache = sz;
}

unsigned sinsp_configuration::get_jmx_limit() const
{
	return m_jmx_limit;
}

void sinsp_configuration::set_jmx_limit(unsigned limit)
{
	m_jmx_limit = std::min(limit, JMX_METRICS_HARD_LIMIT);
}

const std::set<double>& sinsp_configuration::get_percentiles() const
{
	return m_percentiles;
}

void sinsp_configuration::set_percentiles(const std::set<double>& percentiles)
{
	m_percentiles = percentiles;
}

unsigned sinsp_configuration::get_app_checks_limit() const
{
	return m_app_checks_limit;
}

void sinsp_configuration::set_app_checks_limit(unsigned value)
{
	m_app_checks_limit = min(value, APP_METRICS_HARD_LIMIT);
}

bool sinsp_configuration::get_security_enabled() const
{
	return m_security_enabled;
}

void sinsp_configuration::set_security_enabled(bool val)
{
	m_security_enabled = val;
}

bool sinsp_configuration::get_cointerface_enabled() const
{
	return m_cointerface_enabled;
}

void sinsp_configuration::set_cointerface_enabled(bool val)
{
	m_cointerface_enabled = val;
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

uint64_t sinsp_configuration::get_security_baseline_report_interval_ns() const
{
	return m_security_baseline_report_interval_ns;
}

void sinsp_configuration::set_security_baseline_report_interval_ns(uint64_t report_interval)
{
	m_security_baseline_report_interval_ns = report_interval;
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

#endif // HAS_ANALYZER
