#include "common_logger.h"
#include "k8s_audit_infra_state.h"

namespace
{
COMMON_LOGGER();
}

using namespace nlohmann;

json::json_pointer k8s_audit_infra_state::s_objref_resource = "/objectRef/resource"_json_pointer;
json::json_pointer k8s_audit_infra_state::s_objref_name = "/objectRef/name"_json_pointer;
json::json_pointer k8s_audit_infra_state::s_objref_namespace = "/objectRef/namespace"_json_pointer;

k8s_audit_infra_state::k8s_audit_infra_state()
{
}

k8s_audit_infra_state::~k8s_audit_infra_state()
{
}

bool k8s_audit_infra_state::match_scope(json_event *evt,
					const std::string &k8s_cluster_name,
					const std::map<std::string, std::string> &agent_tags,
					const scope_predicates &predicates)
{

	// First see if the agent tags match scope
	::scope_predicates remaining_predicates;

	if(!match_agent_tag_predicates(predicates,
				      agent_tags,
				      remaining_predicates))
	{
		return false;
	}

	scope_resolver_iface::uid_t uid;

	uid.first = "kubernetes.cluster.name";
	uid.second = k8s_cluster_name;

	if(!match_scope(uid, remaining_predicates)) {
		return false;
	}

	const json &j = evt->jevt();

	// For the namespace, if the object in the audit event is
	// itself a namespace, use the object name as the
	// namespace. Otherwise, it will be the namespace property of
	// objectRef,
	std::string resource;

	try {
		resource = j.at(s_objref_resource);
	}
	catch(json::out_of_range &e)
	{
		LOG_DEBUG("object %s did not have /objectRef/resource property", j.dump().c_str());
		return false;
	}
	catch(json::type_error &e)
	{
		LOG_DEBUG("object %s was not a json object", j.dump().c_str());
		return false;
	}

	std::string ns_name;
	const json::json_pointer &ptr = (resource == "namespaces" ?
					 s_objref_name : s_objref_namespace);
	try {
		ns_name = j.at(ptr);
	}
	catch(json::out_of_range &e)
	{
		LOG_DEBUG("object %s did not have %s property", j.dump().c_str(), ptr.to_string().c_str());
		return false;
	}
	catch(json::type_error &e)
	{
		LOG_DEBUG("object %s was not a json object", j.dump().c_str());
		return false;
	}

	uid.first = "kubernetes.namespace.name";
	uid.second = ns_name;

	return match_scope(uid, remaining_predicates);
}

bool k8s_audit_infra_state::match_scope(const uid_t &uid, const scope_predicates &predicates)
{
	if (uid.first == "kubernetes.cluster.name")
	{
		for(auto &pred : predicates)
		{
			if(pred.key() == "kubernetes.cluster.name")
			{
				return match_predicate(pred, uid.second);

			}
		}

		// Predicate didn't have any cluster, so aasume the
		// scope matches.
		return true;
	}
	else if(uid.first == "kubernetes.namespace.name")
	{
		for(auto &pred : predicates)
		{
			if(pred.key() == "kubernetes.namespace.name")
			{
				return match_predicate(pred, uid.second);

			}
		}

		// Predicate didn't have any namespace, so aasume the
		// scope matches.
		return true;
	}

	LOG_DEBUG("Unknown uid key %s", uid.first.c_str());

	return false;
}

