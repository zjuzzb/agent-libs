#pragma once

#include "secure_netsec_obj.h"

namespace draiosproto
{
class container_group;
}

class infrastructure_state;
typedef typename std::shared_ptr<draiosproto::container_group> cg_ptr_t;

const std::string k8s_kind_pod("k8s_pod");
const std::string k8s_kind_node("k8s_node");
const std::string kind_node("node");
const std::string kind_container("container");


/*
 * Helper class for draiosproto::container_group
 */
class secure_netsec_cg
{
	using bistr_function = std::function<void(const std::string&, const std::string&)>;

public:
	inline secure_netsec_cg(const infrastructure_state& infra_state, const cg_ptr_t& cg)
	    : m_cg(cg),
	      m_infra_state(infra_state),
	      m_kind(cg->uid().kind())
	{
	}

	secure_netsec_cg clone(const cg_ptr_t& cg) const { return {m_infra_state, cg}; }

	bool is_pod() const { return m_kind == k8s_kind_pod; }

	bool is_node() const { return m_kind == k8s_kind_node || m_kind == kind_node; }

	bool is_node(const std::string& ip) const;

	bool is_container() const { return m_kind == kind_container; }

	bool is_terminating() const;

	infra_time_point_t pod_creation_tp() const;

	infra_time_point_t tag_ts(const std::string& tag_name) const;

	// Fills out uid and namespace from cg to a k8s_metadata
	void to_metadata(k8s_metadata* meta) const;

	void to_endpoint(k8s_endpoint* k8s_endpoint) const;

	void to_namespace(k8s_namespace* k8s_namespace) const;

	void to_service(k8s_service* k8s_service) const;

	void to_cronjob(k8s_cronjob* k8s_cronjob) const;

	std::unique_ptr<secure::K8SPodOwner> get_k8s_owner() const;

	bool has_container(const std::string& cont_id) const;

	void container_to_pods(std::function<void(const cg_ptr_t& cg)> clbk) const;

	const cg_ptr_t& operator->() const { return m_cg; }
	const cg_ptr_t& get() const { return m_cg; }

	std::string name() const;

private:
	const cg_ptr_t& m_cg;
	const infrastructure_state& m_infra_state;
	const std::string& m_kind;
};
