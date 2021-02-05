#pragma once

#include <set>
#include <string>

#include "json_evt.h"

#include "scope_resolver_iface.h"

// A class that can resolve scopes for k8s audit events (e.g. json
// strings from a k8s api audit log). It supports the following scope keys:
// - kubernetes.cluster.name
// - kubernetes.namespace.name

class k8s_audit_infra_state : public scope_resolver_iface {
public:
	k8s_audit_infra_state();
	virtual ~k8s_audit_infra_state();

	// Main entrypoint, using an event.
	bool match_scope(json_event *evt, const std::string k8s_cluster_name, const scope_predicates &predicates);

	// This should be called twice--once where uid is
	// (kubernetes.cluster.name, <cluster name>) and once where
	// uid is (kubernetes.namespace.name, <namespace from some
	// json_event).
	bool match_scope(const uid_t &uid, const scope_predicates &predicates) override;

private:
	std::string m_k8s_cluster_name;
	static nlohmann::json::json_pointer s_objref_resource;
	static nlohmann::json::json_pointer s_objref_name;
	static nlohmann::json::json_pointer s_objref_namespace;
};
