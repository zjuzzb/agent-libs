#ifdef HAS_ANALYZER

#pragma once
#include <bitset>
#ifdef max
#undef max
#endif
#include <limits>

#include "user_event.h"
#include "metric_limits.h"
#include "label_limits.h"
#ifndef CYGWING_AGENT
#include "mesos.h"
#endif

using ports_set = bitset<numeric_limits<uint16_t>::max()+1>;

// fwd declaration
namespace proc_filter {
class conf;
class group_pctl_conf;
};

class SINSP_PUBLIC sinsp_configuration
{
public:
	enum command_capture_mode_t
	{
		CM_TTY = 0,
		CM_SHELL_ANCESTOR = 1,
		CM_ALL = 2
	};

	typedef std::set<std::string>      k8s_ext_list_t;
	typedef shared_ptr<k8s_ext_list_t> k8s_ext_list_ptr_t;

	sinsp_configuration();
	sinsp_configuration(const sinsp_configuration& configuration);
	uint64_t get_connection_timeout_ns() const;
	uint64_t get_connection_timeout_sec() const;
	void set_connection_timeout_in_sec(uint64_t timeout_sec);
	uint64_t get_connection_pruning_interval_ns() const;
	void set_connection_pruning_interval_ns(uint64_t interval_ns);
	bool get_emit_metrics_to_file() const;
	void set_emit_metrics_to_file(bool emit);
	bool get_compress_metrics() const;
	void set_compress_metrics(bool compress);
	const string& get_metrics_directory() const;
	void set_metrics_directory(string metrics_directory);
	sinsp_logger::output_type get_log_output_type() const;
	void set_log_output_type(sinsp_logger::output_type log_output_type);
	const string& get_machine_id() const;
	void set_machine_id(string machine_id);
	const string& get_customer_id() const;
	void set_customer_id(string customer_id);
	uint64_t get_analyzer_sample_len_ns() const;
	uint64_t get_analyzer_original_sample_len_ns() const;
	void set_analyzer_sample_len_ns(uint64_t analyzer_sample_length_ns);
	uint32_t get_max_connection_table_size() const;
	void set_max_connection_table_size(uint32_t max_connection_table_size);
	uint32_t get_max_connections_in_proto() const;
	void set_max_connections_in_proto(uint32_t max_connections_in_proto);
	bool get_aggregate_connections_in_proto() const;
	void set_aggregate_connections_in_proto(bool aggregate);
	bool get_autodrop_enabled() const;
	void set_autodrop_enabled(bool enabled);
	uint32_t get_drop_upper_threshold(uint32_t nprocs) const;
	void set_drop_upper_threshold(uint32_t drop_upper_threshold);
	uint32_t get_drop_lower_threshold(uint32_t nprocs) const;
	void set_drop_lower_threshold(uint32_t drop_lower_threshold);
	uint32_t get_drop_threshold_consecutive_seconds() const;
	void set_drop_threshold_consecutive_seconds(uint32_t drop_threshold_consecutive_seconds);
	const string& get_host_custom_name() const;
	void set_host_custom_name(string host_custom_name);
	const string& get_host_tags() const;
	void set_host_tags(const string& host_tags);
	bool get_host_hidden() const;
	void set_host_hidden(bool host_hidden);
	const string& get_hidden_processes() const;
	void set_hidden_processes(string hidden_processes);
	const string& get_host_custom_map() const;
	void set_host_custom_map(string host_custom_map);
	const string& get_version() const;
	void set_version(const string& version);
	const string& get_instance_id() const;
	void set_instance_id(const string& instance_id);
	void set_known_ports(const ports_set & v);
	const ports_set & get_known_ports() const;
	void set_blacklisted_ports(const vector<uint16_t> & v);
	void set_blacklisted_ports(const ports_set & v);
	const ports_set & get_blacklisted_ports() const;
	unsigned get_statsd_limit() const;
	void set_statsd_limit(unsigned value);
	bool get_use_host_statsd() const;
	void set_use_host_statsd(bool value);
#ifndef CYGWING_AGENT
	void set_k8s_api_server(const string& k8s_api);
	const string & get_k8s_api_server() const;
	bool get_k8s_autodetect_enabled() const;
	void set_k8s_autodetect_enabled(bool enabled);
	void set_k8s_ssl_cert_type(const string& k8s_ssl_cert_type);
	const string & get_k8s_ssl_cert_type() const;
	void set_k8s_ssl_cert(const string& k8s_ssl_cert);
	const string & get_k8s_ssl_cert() const;
	void set_k8s_ssl_key(const string& k8s_ssl_key);
	const string & get_k8s_ssl_key() const;
	void set_k8s_ssl_key_password(const string& k8s_ssl_key_password);
	const string & get_k8s_ssl_key_password() const;
	void set_k8s_ssl_ca_certificate(const string& k8s_ssl_ca_cert);
	const string & get_k8s_ssl_ca_certificate() const;
	void set_k8s_ssl_verify_certificate(bool k8s_ssl_ca_cert);
	bool get_k8s_ssl_verify_certificate() const;
	void set_k8s_timeout_s(uint64_t k8s_timeout_s);
	uint64_t get_k8s_timeout_s() const;
	void set_k8s_simulate_delegation(bool k8s_simulate_delegation);
	bool get_k8s_simulate_delegation() const;
	void set_k8s_delegated_nodes(int k8s_delegated_nodes);
	int get_k8s_delegated_nodes() const;
	void set_k8s_bt_auth_token(const string& k8s_bt_auth_token);
	const string & get_k8s_bt_auth_token() const;
	void set_k8s_extensions(const std::set<std::string>& k8s_extensions);
	const std::set<std::string>& get_k8s_extensions() const;
	void set_k8s_cluster_name(const std::string &k8s_cluster_name);
	const std::string& get_k8s_cluster_name() const;
	void set_k8s_include_types(const vector<string> &types);
	const vector<string> & get_k8s_include_types() const;
	void set_k8s_event_counts_log_time(uint32_t log_time);
	uint32_t get_k8s_event_counts_log_time() const;
	string get_mesos_state_uri() const;
	void set_mesos_state_uri(const string & uri);
	string get_mesos_state_original_uri() const;
	const vector<string> & get_marathon_uris() const;
	void set_marathon_uris(const vector<string> & uris);
	bool get_mesos_autodetect_enabled() const;
	void set_mesos_autodetect_enabled(bool enabled);
	void set_mesos_timeout_ms(int mesos_timeout_ms);
	int get_mesos_timeout_ms() const;
	bool get_mesos_follow_leader() const;
	void set_mesos_follow_leader(bool enabled);
	bool get_marathon_follow_leader() const;
	void set_marathon_follow_leader(bool enabled);
	const mesos::credentials_t& get_mesos_credentials() const;
	void set_mesos_credentials(const mesos::credentials_t& creds);
	const mesos::credentials_t& get_marathon_credentials() const;
	void set_marathon_credentials(const mesos::credentials_t& creds);
	const mesos::credentials_t& get_dcos_enterprise_credentials() const;
	void set_marathon_skip_labels(std::set<std::string> &labels);
	const std::set<std::string>& get_marathon_skip_labels() const;
	void set_dcos_enterprise_credentials(const mesos::credentials_t& creds);
#endif // CYGWING_AGENT
	bool get_curl_debug() const;
	void set_curl_debug(bool enabled);
	uint32_t get_protocols_truncation_size() const;
	void set_protocols_truncation_size(uint32_t truncation_size);
	user_event_filter_t::ptr_t get_k8s_event_filter() const;
	void set_k8s_event_filter(user_event_filter_t::ptr_t event_filter);
	user_event_filter_t::ptr_t get_docker_event_filter() const;
	void set_docker_event_filter(user_event_filter_t::ptr_t event_filter);
	filter_vec_t get_metrics_filter() const;
	filter_vec_t get_labels_filter() const;
	void set_metrics_filter(const filter_vec_t& event_filter);
	void set_k8s_filter(const filter_vec_t& filter);
	filter_vec_t get_k8s_filter(void) const;
	filter_vec_t get_mounts_filter() const;
	void set_labels_filter(const filter_vec_t& labels_filter);
	void set_mounts_filter(const filter_vec_t& mount_filter);
	unsigned get_mounts_limit_size() const;
	void set_mounts_limit_size(unsigned mounts_limit_size);
	bool get_excess_metrics_log() const;
	unsigned get_metrics_cache() const;
	void set_excess_labels_log(bool log) noexcept;
	bool get_excess_labels_log() const noexcept;
	void set_labels_cache(uint16_t size) noexcept;
	uint16_t get_labels_cache(void) const noexcept;
	void set_excess_metrics_log(bool log);
	void set_metrics_cache(unsigned sz);
	void set_k8s_cache(uint16_t size) noexcept;
	uint16_t get_k8s_cache() const noexcept;
	void set_excess_k8s_log(bool) noexcept;
	bool get_excess_k8s_log(void) const noexcept;
	bool get_falco_baselining_enabled() const;
	void set_falco_baselining_enabled(bool enabled);
	bool get_command_lines_capture_enabled() const;
	void set_command_lines_capture_enabled(bool enabled);
	command_capture_mode_t get_command_lines_capture_mode() const;
	void set_command_lines_capture_mode(command_capture_mode_t capture_mode);
	void set_command_lines_include_container_healthchecks(bool enabled);
	bool get_command_lines_include_container_healthchecks() const;
	set<string> get_command_lines_valid_ancestors() const;
	void set_command_lines_valid_ancestors(const set<string>& valid_ancestors);
	bool is_command_lines_valid_ancestor(const string& ancestor) const;
	bool get_capture_dragent_events() const;
	void set_capture_dragent_events(bool enabled);
	uint64_t get_memdump_size() const;
	void set_memdump_size(uint64_t size);
	unsigned get_jmx_limit() const;
	void set_jmx_limit(unsigned limit);
	const std::set<double>& get_percentiles() const;
	shared_ptr<proc_filter::group_pctl_conf> get_group_pctl_conf() const;
	void set_percentiles(const std::set<double>&, shared_ptr<proc_filter::group_pctl_conf>);
	shared_ptr<proc_filter::conf> get_container_filter() const;

	void set_log_dir(string& dir);
	string& get_log_dir();

	void set_container_filter(shared_ptr<proc_filter::conf>);

	void set_smart_container_reporting(bool);
	bool get_smart_container_reporting() const;

	void set_dragent_cpu_profile_enabled(bool enabled);
	void set_dragent_profile_time_seconds(uint32_t seconds);
	void set_dragent_total_profiles(uint32_t count);
	bool get_dragent_cpu_profile_enabled() const;
	uint32_t get_dragent_profile_time_seconds() const;
	uint32_t get_dragent_total_profiles() const;

	uint32_t get_statsite_buffer_warning_length() const;
	void set_statsite_buffer_warning_length(uint32_t len);

	unsigned get_app_checks_limit() const;
	void set_app_checks_limit(unsigned value);
	bool get_app_checks_always_send() const;
	void set_app_checks_always_send(bool);
	bool get_security_enabled() const;
	void set_security_enabled(bool enabled);
	bool get_cointerface_enabled() const;
	void set_cointerface_enabled(bool enabled);
	bool get_detect_stress_tools() const;
	void set_detect_stress_tools(bool enabled);
	bool get_swarm_enabled() const;
	void set_swarm_enabled(bool enabled);
	uint64_t get_security_baseline_report_interval_ns() const;
	void set_security_baseline_report_interval_ns(uint64_t report_interval);

	const pair<long, unsigned>& get_tracepoint_hits_threshold() const;
	void set_tracepoint_hits_threshold(long, unsigned);
	const pair<double, unsigned>& get_cpu_max_sr_threshold() const;
	void set_cpu_max_sr_threshold(double, unsigned);

	uint32_t get_orch_queue_len() const;
	void set_orch_queue_len(uint32_t queue_len);
	int32_t get_orch_gc() const;
	void set_orch_gc(int32_t gc);
	uint32_t get_orch_inf_wait_time_s() const;
	void set_orch_inf_wait_time_s(uint32_t inf_wait_time_s);
	uint32_t get_orch_tick_interval_ms() const;
	void set_orch_tick_interval_ms(uint32_t tick_interval_ms);
	uint32_t get_orch_low_ticks_needed() const;
	void set_orch_low_ticks_needed(uint32_t low_ticks_needed);
	uint32_t get_orch_low_evt_threshold() const;
	void set_orch_low_evt_threshold(uint32_t low_evt_threshold);
	bool get_orch_filter_empty() const;
	void set_orch_filter_empty(bool filter_empty);
	uint32_t get_orch_batch_msgs_queue_len() const;
	void set_orch_batch_msgs_queue_len(uint32_t batch_queue_len);
	uint32_t get_orch_batch_msgs_tick_interval_ms() const;
	void set_orch_batch_msgs_tick_interval_ms(uint32_t batch_tick_interval_ms);
private:
	string get_mesos_uri(const std::string& sought_url) const;
	void set_mesos_uri(string& url, const string & new_url);
	void set_mesos_state_original_uri(const string & uri);
	friend class sinsp_worker;

	uint64_t m_connection_pruning_interval_ns;
	uint64_t m_connection_timeout_ns;
	bool m_emit_metrics_to_file;
	bool m_compress_metrics;
	string m_machine_id;
	string m_customer_id;
	uint64_t m_analyzer_sample_len_ns;
	uint64_t m_analyzer_original_sample_len_ns;
	string m_metrics_directory;
	uint32_t m_max_connection_table_size;
	uint32_t m_max_connections_in_proto;
	bool m_aggregate_connections_in_proto;
	bool m_autodrop_enabled;
	uint32_t m_drop_upper_threshold;
	uint32_t m_drop_lower_threshold;
	uint32_t m_drop_threshold_consecutive_seconds;
	string m_host_custom_name;
	string m_host_tags;
	bool m_host_hidden;
	string m_hidden_processes;
	string m_host_custom_map;
	string m_version;
	string m_instance_id;
	ports_set m_known_ports;
	ports_set m_blacklisted_ports;

	std::set<double> m_percentiles;
	unsigned m_statsd_limit;
	bool m_use_host_statsd;
	shared_ptr<proc_filter::group_pctl_conf> m_group_pctl_conf;
	shared_ptr<proc_filter::conf> m_container_filter;
	bool m_smart_container_reporting = false;

	string m_log_dir;

	bool m_dragent_cpu_profile_enabled;
	uint32_t m_dragent_profile_time_seconds;
	uint32_t m_dragent_total_profiles;

	uint32_t m_statsite_buffer_warning_length;

#ifndef CYGWING_AGENT	
	string m_k8s_api;
	bool   m_k8s_autodetect;
	string m_k8s_ssl_cert_type;
	string m_k8s_ssl_cert;
	string m_k8s_ssl_key;
	string m_k8s_ssl_key_password;
	string m_k8s_ssl_ca_certificate;
	bool m_k8s_ssl_verify_certificate;
	uint64_t m_k8s_timeout_s;
	string m_k8s_bt_auth_token;
	int m_k8s_delegated_nodes;
	bool m_k8s_simulate_delegation;
	std::set<std::string> m_k8s_extensions;
	std::string m_k8s_cluster_name;
	vector<string> m_k8s_include_types;
	uint32_t m_k8s_event_counts_log_time;

	string m_mesos_state_uri;
	string m_mesos_state_original_uri;
	mutable vector<string> m_marathon_uris;
	bool m_mesos_autodetect;
	int m_mesos_timeout_ms;
	bool m_mesos_follow_leader;
	bool m_marathon_follow_leader;
	mesos::credentials_t m_mesos_credentials;
	mesos::credentials_t m_marathon_credentials;
	mesos::credentials_t m_dcos_enterprise_credentials;
	std::set<std::string> m_marathon_skip_labels;
#endif // CYGWING_AGENT

	bool m_curl_debug;

	bool m_falco_baselining_enabled;
	bool m_command_lines_capture_enabled;
	command_capture_mode_t m_command_lines_capture_mode;
	bool m_command_lines_include_container_healthchecks;
	set<string> m_command_lines_valid_ancestors;
	bool m_capture_dragent_events;
	uint64_t m_memdump_size;

	uint32_t m_protocols_truncation_size;

	std::shared_ptr<user_event_filter_t> m_k8s_event_filter;
	std::shared_ptr<user_event_filter_t> m_docker_event_filter;

	filter_vec_t m_metrics_filter;
	filter_vec_t m_labels_filter;
	bool m_excess_metrics_log = false;
	unsigned m_metrics_cache = 0;
	bool m_excess_labels_log = false;
	uint16_t m_labels_cache = 0;

	filter_vec_t m_k8s_filter;
	bool m_excess_k8s_log = false;
	uint16_t m_k8s_cache = 0;

	filter_vec_t m_mounts_filter;
	unsigned m_mounts_limit_size;

	unsigned m_jmx_limit;
	unsigned m_app_checks_limit;
	bool m_app_checks_always_send;

	bool m_detect_stress_tools;
	bool m_security_enabled;
	bool m_cointerface_enabled;
	bool m_swarm_enabled;

	uint64_t m_security_baseline_report_interval_ns;

	pair<long, unsigned> m_tracepoint_hits_threshold;
	pair<double, unsigned> m_cpu_max_sr_threshold;

	uint32_t m_orch_queue_len;
	int32_t m_orch_gc;
	uint32_t m_orch_inf_wait_time_s;
	uint32_t m_orch_tick_interval_ms;
	uint32_t m_orch_low_ticks_needed;
	uint32_t m_orch_low_evt_threshold;
	bool m_orch_filter_empty;
	uint32_t m_orch_batch_msgs_queue_len;
	uint32_t m_orch_batch_msgs_tick_interval_ms;
};

#endif // HAS_ANALYZER
