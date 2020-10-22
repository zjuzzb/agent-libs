#include "test_security_stub.h"

test_infrastructure_state::test_infrastructure_state()
{
}

test_infrastructure_state::~test_infrastructure_state()
{
}

void test_infrastructure_state::clear_scope_cache()
{
}

int test_infrastructure_state::find_tag_list(infrastructure_state_iface::uid_t uid,
					     std::unordered_set<string> &tags_set,
					     std::unordered_map<string,
					     string> &labels) const
{
	return 0;
}

std::string test_infrastructure_state::get_k8s_cluster_name()
{
	return string("test-cluster");
}

std::string test_infrastructure_state::get_k8s_pod_uid(const std::string &namespace_name,
						       const std::string &pod_name) const
{
	return string("fake-uid");
}

bool test_infrastructure_state::find_tag(const infrastructure_state_iface::uid_t& uid,
					 const std::string& tag,
					 std::string &value) const
{
	return false;
}

int test_infrastructure_state::get_tags(infrastructure_state_iface::uid_t uid,
					std::unordered_map<string,
					string>& tags_map) const
{
	return 0;
}

bool test_infrastructure_state::match_scope(const infrastructure_state_iface::uid_t &uid,
					    const scope_predicates &predicates)
{
	return true;
}

bool test_infrastructure_state::register_scope(reg_id_t &reg,
		    bool host_scope, bool container_scope,
		    const scope_predicates &predicates)
{
	return true;
}

bool test_infrastructure_state::check_registered_scope(reg_id_t &reg) const
{
	return true;
}

std::string test_infrastructure_state::get_machine_id() const
{
	return string("fake-machine-id");
}

sinsp_container_info::ptr_t test_infrastructure_state::get_container_info(const std::string& container_id)
{
	return nullptr;
}

void  test_secure_k8s_audit_event_sink::receive_k8s_audit_event(
	const nlohmann::json& j,
	std::vector<std::string>& k8s_active_filters,
	std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters)
{
}

test_capture_job_queue_handler::test_capture_job_queue_handler()
{
}

test_capture_job_queue_handler::~test_capture_job_queue_handler()
{
}

bool test_capture_job_queue_handler::queue_job_request(sinsp *inspector,
						       std::shared_ptr<dump_job_request> job_request,
						       std::string &errstr)
{
	m_job_requests.push_back(job_request);
	return true;
}
