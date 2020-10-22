#pragma once

#include <analyzer.h>
#include <capture_job_handler.h>
#include <infrastructure_state.h>

// Stub infra state that just allows the tests to work without a full analyzer
class test_infrastructure_state : public infrastructure_state_iface
{
public:

	test_infrastructure_state();

	virtual ~test_infrastructure_state();

	void clear_scope_cache();

	int find_tag_list(infrastructure_state_iface::uid_t uid, std::unordered_set<string> &tags_set, std::unordered_map<string, string> &labels) const;

	std::string get_k8s_cluster_name();

	std::string get_k8s_pod_uid(const std::string &namespace_name, const std::string &pod_name) const;

	bool find_tag(const infrastructure_state_iface::uid_t& uid, const std::string& tag, std::string &value) const;

	int get_tags(infrastructure_state_iface::uid_t uid, std::unordered_map<string, string>& tags_map) const;

	bool match_scope(const infrastructure_state_iface::uid_t &uid, const scope_predicates &predicates);

	bool register_scope(reg_id_t &reg,
			    bool host_scope, bool container_scope,
			    const scope_predicates &predicates);

	bool check_registered_scope(reg_id_t &reg) const;

	std::string get_machine_id() const;

	sinsp_container_info::ptr_t get_container_info(const std::string& container_id);
};

class test_secure_k8s_audit_event_sink : public secure_k8s_audit_event_sink_iface
{
public:
	test_secure_k8s_audit_event_sink() {};
	virtual ~test_secure_k8s_audit_event_sink() {};

	void receive_k8s_audit_event(
		const nlohmann::json& j,
		std::vector<std::string>& k8s_active_filters,
		std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters);
};

class test_capture_job_queue_handler :
		public capture_job_queue_handler
{
public:
	test_capture_job_queue_handler();

	virtual ~test_capture_job_queue_handler();

	bool queue_job_request(sinsp *inspector, std::shared_ptr<dump_job_request> job_request, std::string &errstr);

	std::vector<std::shared_ptr<dump_job_request>> m_job_requests;
};
