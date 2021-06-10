#pragma once

#include <bitset>
#ifdef max
#undef max
#endif
#include "label_limits.h"
#include "metric_limits.h"
#include "user_event.h"

#include <limits>
#ifndef CYGWING_AGENT
#include "mesos.h"
#endif

using ports_set = std::bitset<std::numeric_limits<uint16_t>::max() + 1>;

// fwd declaration
namespace proc_filter
{
class conf;
class group_pctl_conf;
};  // namespace proc_filter

class SINSP_PUBLIC sinsp_configuration
{
public:
	enum command_capture_mode_t
	{
		CM_TTY = 0,
		CM_SHELL_ANCESTOR = 1,
		CM_ALL = 2
	};

	typedef std::set<std::string> k8s_ext_list_t;
	typedef std::shared_ptr<k8s_ext_list_t> k8s_ext_list_ptr_t;

	sinsp_configuration();

	// There was previously an incomplete copy constructor.  We removed
	// it and marked it deleted to ensure no one was using it.  If we
	// need to copy this in the future, the default might be sufficient.
	sinsp_configuration(const sinsp_configuration& configuration) = delete;

	const std::string& get_machine_id() const;
	void set_machine_id(const std::string& machine_id);
	const std::string& get_customer_id() const;
	void set_customer_id(const std::string& customer_id);
	const std::string& get_version() const;
	void set_version(const std::string& version);
	const std::string& get_instance_id() const;
	void set_instance_id(const std::string& instance_id);
	const std::string& get_account_id() const;
	void set_account_id(const std::string& account_id);
	const std::string& get_region() const;
	void set_region(const std::string& region);
#ifndef CYGWING_AGENT
	void set_k8s_delegated_nodes(int k8s_delegated_nodes);
	int get_k8s_delegated_nodes() const;
	void set_k8s_extensions(const std::set<std::string>& k8s_extensions);
	const std::set<std::string>& get_k8s_extensions() const;
	void set_k8s_cluster_name(const std::string& k8s_cluster_name);
	const std::string& get_k8s_cluster_name() const;
	std::string get_mesos_state_uri() const;
	void set_mesos_state_uri(const std::string& uri);
	std::string get_mesos_state_original_uri() const;
	const std::vector<std::string>& get_marathon_uris() const;
	void set_marathon_uris(const std::vector<std::string>& uris);
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
	void set_marathon_skip_labels(const std::set<std::string>& labels);
	const std::set<std::string>& get_marathon_skip_labels() const;
	void set_dcos_enterprise_credentials(const mesos::credentials_t& creds);
#endif  // CYGWING_AGENT
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
	filter_vec_t get_mounts_filter() const;
	void set_mounts_filter(const filter_vec_t& mount_filter);
	unsigned get_mounts_limit_size() const;
	void set_mounts_limit_size(unsigned mounts_limit_size);

	bool get_executed_commands_capture_enabled() const;
	void set_executed_commands_capture_enabled(bool enabled);
	command_capture_mode_t get_command_lines_capture_mode() const;
	void set_command_lines_capture_mode(command_capture_mode_t capture_mode);
	void set_command_lines_include_container_healthchecks(bool enabled);
	bool get_command_lines_include_container_healthchecks() const;
	std::set<std::string> get_command_lines_valid_ancestors() const;
	void set_command_lines_valid_ancestors(const std::set<std::string>& valid_ancestors);
	bool is_command_lines_valid_ancestor(const std::string& ancestor) const;
	bool get_capture_dragent_events() const;
	void set_capture_dragent_events(bool enabled);

	const std::set<double>& get_percentiles() const;
	std::shared_ptr<proc_filter::group_pctl_conf> get_group_pctl_conf() const;
	void set_percentiles(const std::set<double>&, std::shared_ptr<proc_filter::group_pctl_conf>);
	std::shared_ptr<proc_filter::conf> get_container_filter() const;

	void set_log_dir(const std::string& dir);
	std::string& get_log_dir();

	void set_container_filter(std::shared_ptr<proc_filter::conf>);

	void set_go_k8s_user_events(bool);
	bool get_go_k8s_user_events() const;

	bool get_detect_stress_tools() const;
	void set_detect_stress_tools(bool enabled);

	const std::pair<long, unsigned>& get_tracepoint_hits_threshold() const;
	void set_tracepoint_hits_threshold(long, unsigned);
	const std::pair<double, unsigned>& get_cpu_max_sr_threshold() const;
	void set_cpu_max_sr_threshold(double, unsigned);

	void set_procfs_scan_procs(const std::set<std::string>& procs);
	const std::set<std::string>& get_procfs_scan_procs();

private:
	std::string get_mesos_uri(const std::string& sought_url) const;
	void set_mesos_uri(std::string& url, const std::string& new_url);
	void set_mesos_state_original_uri(const std::string& uri);
	friend class dragent_app;

	std::string m_machine_id;
	std::string m_customer_id;
	std::string m_version;
	std::string m_instance_id;
	std::string m_account_id;
	std::string m_region;

	std::set<double> m_percentiles;
	std::shared_ptr<proc_filter::group_pctl_conf> m_group_pctl_conf;
	std::shared_ptr<proc_filter::conf> m_container_filter;

	/**
	 * Enable to route K8s user events through cointerface instead of dragent
	 * dragent will only serve as a middleman in this case. Leave false
	 * to cause dragent to directly talk to K8s API server to fetch events
	 */
	bool m_go_k8s_user_events = false;
	bool m_go_k8s_debug_events = false;

	std::string m_log_dir;

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
#endif  // CYGWING_AGENT

	bool m_curl_debug;

	bool m_executed_commands_capture_enabled;
	command_capture_mode_t m_command_lines_capture_mode;
	bool m_command_lines_include_container_healthchecks;
	std::set<std::string> m_command_lines_valid_ancestors;
	bool m_capture_dragent_events;

	uint32_t m_protocols_truncation_size;

	std::shared_ptr<user_event_filter_t> m_k8s_event_filter;
	std::shared_ptr<user_event_filter_t> m_docker_event_filter;
	std::shared_ptr<user_event_filter_t> m_containerd_event_filter;

	filter_vec_t m_mounts_filter;
	unsigned m_mounts_limit_size;

	unsigned m_jmx_limit;

	bool m_detect_stress_tools;

	std::pair<long, unsigned> m_tracepoint_hits_threshold;
	std::pair<double, unsigned> m_cpu_max_sr_threshold;

	std::set<std::string> m_procfs_scan_procs;
};
