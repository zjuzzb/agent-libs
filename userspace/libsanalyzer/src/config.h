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

using ports_set = std::bitset<std::numeric_limits<uint16_t>::max()+1>;

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
	typedef std::shared_ptr<k8s_ext_list_t> k8s_ext_list_ptr_t;

	sinsp_configuration();

	// There was previously an incomplete copy constructor.  We removed
	// it and marked it deleted to ensure no one was using it.  If we
	// need to copy this in the future, the default might be sufficient.
	sinsp_configuration(const sinsp_configuration& configuration) = delete;

	uint64_t get_connection_timeout_ns() const;
	uint64_t get_connection_timeout_sec() const;
	void set_connection_timeout_in_sec(uint64_t timeout_sec);
	uint64_t get_connection_pruning_interval_ns() const;
	void set_connection_pruning_interval_ns(uint64_t interval_ns);
	const std::string& get_machine_id() const;
	void set_machine_id(std::string machine_id);
	const std::string& get_customer_id() const;
	void set_customer_id(std::string customer_id);
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
	const std::string& get_host_custom_name() const;
	void set_host_custom_name(std::string host_custom_name);
	const std::string& get_host_tags() const;
	void set_host_tags(const std::string& host_tags);
	bool get_host_hidden() const;
	void set_host_hidden(bool host_hidden);
	const std::string& get_hidden_processes() const;
	void set_hidden_processes(std::string hidden_processes);
	const std::string& get_host_custom_map() const;
	void set_host_custom_map(std::string host_custom_map);
	const std::string& get_version() const;
	void set_version(const std::string& version);
	const std::string& get_instance_id() const;
	void set_instance_id(const std::string& instance_id);
	void set_known_ports(const ports_set & v);
	const ports_set & get_known_ports() const;
	void set_blacklisted_ports(const std::vector<uint16_t> & v);
	void set_blacklisted_ports(const ports_set & v);
	const ports_set & get_blacklisted_ports() const;
#ifndef CYGWING_AGENT
	void set_k8s_delegated_nodes(int k8s_delegated_nodes);
	int get_k8s_delegated_nodes() const;
	void set_k8s_extensions(const std::set<std::string>& k8s_extensions);
	const std::set<std::string>& get_k8s_extensions() const;
	void set_k8s_cluster_name(const std::string &k8s_cluster_name);
	const std::string& get_k8s_cluster_name() const;
	std::string get_mesos_state_uri() const;
	void set_mesos_state_uri(const std::string & uri);
	std::string get_mesos_state_original_uri() const;
	const std::vector<std::string> & get_marathon_uris() const;
	void set_marathon_uris(const std::vector<std::string> & uris);
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
	void set_marathon_skip_labels(const std::set<std::string> &labels);
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
	user_event_filter_t::ptr_t get_containerd_event_filter() const;
	void set_containerd_event_filter(user_event_filter_t::ptr_t event_filter);
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
	std::set<std::string> get_command_lines_valid_ancestors() const;
	void set_command_lines_valid_ancestors(const std::set<std::string>& valid_ancestors);
	bool is_command_lines_valid_ancestor(const std::string& ancestor) const;
	bool get_capture_dragent_events() const;
	void set_capture_dragent_events(bool enabled);
	uint64_t get_memdump_size() const;
	void set_memdump_size(uint64_t size);
	const std::set<double>& get_percentiles() const;
	std::shared_ptr<proc_filter::group_pctl_conf> get_group_pctl_conf() const;
	void set_percentiles(const std::set<double>&, std::shared_ptr<proc_filter::group_pctl_conf>);
	std::shared_ptr<proc_filter::conf> get_container_filter() const;

	void set_log_dir(const std::string& dir);
	std::string& get_log_dir();

	void set_container_filter(std::shared_ptr<proc_filter::conf>);

	void set_smart_container_reporting(bool);
	bool get_smart_container_reporting() const;

	void set_go_k8s_user_events(bool);
	bool get_go_k8s_user_events() const;
	void set_go_k8s_debug_events(bool);
	bool get_go_k8s_debug_events() const;
	void set_add_event_scopes(bool);
	bool get_add_event_scopes() const;

	void set_dragent_cpu_profile_enabled(bool enabled);
	void set_dragent_profile_time_seconds(uint32_t seconds);
	void set_dragent_total_profiles(uint32_t count);
	bool get_dragent_cpu_profile_enabled() const;
	uint32_t get_dragent_profile_time_seconds() const;
	uint32_t get_dragent_total_profiles() const;

	bool get_statsite_check_format() const;
	void set_statsite_check_format(bool enabled);

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

	const std::pair<long, unsigned>& get_tracepoint_hits_threshold() const;
	void set_tracepoint_hits_threshold(long, unsigned);
	const std::pair<double, unsigned>& get_cpu_max_sr_threshold() const;
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
	void set_procfs_scan_delay_ms(uint32_t scan_delay_ms);
	uint32_t get_procfs_scan_delay_ms() const;
	void set_procfs_scan_interval_ms(uint32_t scan_interval_ms);
	uint32_t get_procfs_scan_interval_ms() const;
	void set_procfs_scan_mem_interval_ms(uint32_t scan_interval_ms);
	uint32_t get_procfs_scan_mem_interval_ms() const;
	uint32_t get_orch_batch_msgs_queue_len() const;
	void set_orch_batch_msgs_queue_len(uint32_t batch_queue_len);
	uint32_t get_orch_batch_msgs_tick_interval_ms() const;
	void set_orch_batch_msgs_tick_interval_ms(uint32_t batch_tick_interval_ms);
	void set_procfs_scan_procs(const std::set<std::string> &procs, uint32_t interval);
	const std::set<std::string> &get_procfs_scan_procs();
	uint32_t get_procfs_scan_interval();
private:
	std::string get_mesos_uri(const std::string& sought_url) const;
	void set_mesos_uri(std::string& url, const std::string & new_url);
	void set_mesos_state_original_uri(const std::string & uri);
	friend class sinsp_worker;

	uint64_t m_connection_pruning_interval_ns;
	uint64_t m_connection_timeout_ns;
	std::string m_machine_id;
	std::string m_customer_id;
	uint64_t m_analyzer_sample_len_ns;
	uint64_t m_analyzer_original_sample_len_ns;
	uint32_t m_max_connection_table_size;
	uint32_t m_max_connections_in_proto;
	bool m_aggregate_connections_in_proto;
	bool m_autodrop_enabled;
	uint32_t m_drop_upper_threshold;
	uint32_t m_drop_lower_threshold;
	uint32_t m_drop_threshold_consecutive_seconds;
	std::string m_host_custom_name;
	std::string m_host_tags;
	bool m_host_hidden;
	std::string m_hidden_processes;
	std::string m_host_custom_map;
	std::string m_version;
	std::string m_instance_id;
	ports_set m_known_ports;
	ports_set m_blacklisted_ports;

	std::set<double> m_percentiles;
	std::shared_ptr<proc_filter::group_pctl_conf> m_group_pctl_conf;
	std::shared_ptr<proc_filter::conf> m_container_filter;
	bool m_smart_container_reporting = false;

	/**
         * Enable to route K8s user events through cointerface instead of dragent
         * dragent will only serve as a middleman in this case. Leave false
         * to cause dragent to directly talk to K8s API server to fetch events
         */
	bool m_go_k8s_user_events = false;
	bool m_go_k8s_debug_events = false;
	bool m_add_event_scopes = false;

	std::string m_log_dir;

	bool m_dragent_cpu_profile_enabled;
	uint32_t m_dragent_profile_time_seconds;
	uint32_t m_dragent_total_profiles;

	bool m_statsite_check_format;

#ifndef CYGWING_AGENT	
	int m_k8s_delegated_nodes;
	std::set<std::string> m_k8s_extensions;
	std::string m_k8s_cluster_name;

	std::string m_mesos_state_uri;
	std::string m_mesos_state_original_uri;
	mutable std::vector<std::string> m_marathon_uris;
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
	std::set<std::string> m_command_lines_valid_ancestors;
	bool m_capture_dragent_events;
	uint64_t m_memdump_size;

	uint32_t m_protocols_truncation_size;

	std::shared_ptr<user_event_filter_t> m_k8s_event_filter;
	std::shared_ptr<user_event_filter_t> m_docker_event_filter;
	std::shared_ptr<user_event_filter_t> m_containerd_event_filter;

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
	bool m_app_checks_always_send;

	bool m_detect_stress_tools;
	bool m_security_enabled;
	bool m_cointerface_enabled;
	bool m_swarm_enabled;

	uint64_t m_security_baseline_report_interval_ns;

	std::pair<long, unsigned> m_tracepoint_hits_threshold;
	std::pair<double, unsigned> m_cpu_max_sr_threshold;

	uint32_t m_procfs_scan_delay_ms;
	uint32_t m_procfs_scan_interval_ms;
	uint32_t m_procfs_scan_mem_interval_ms;

	uint32_t m_orch_batch_msgs_queue_len;
	uint32_t m_orch_batch_msgs_tick_interval_ms;

	std::set<std::string> m_procfs_scan_procs;
	uint32_t m_procfs_scan_interval;
};
