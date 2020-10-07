#include "infra_utils_details.h"

// Fully specialized template functions are defined in a compile unit instead of an header
// file, as they follow the one definition point rule.
namespace test
{
namespace details
{
template<>
void set_namespace<draiosproto::k8s_namespace>(draiosproto::k8s_namespace& obj,
                                               const std::string& ns)
{
	obj.mutable_common()->set_namespace_("");
}

template<>
void set_namespace<draiosproto::k8s_node>(draiosproto::k8s_node& obj, const std::string& ns)
{
}

template<>
void set_node<draiosproto::k8s_pod>(draiosproto::k8s_pod& pod, const std::string& ns_name)
{
	pod.set_node_name(ns_name);
}

template<>
void set_restart_rate<draiosproto::k8s_pod>(draiosproto::k8s_pod& pod)
{
	pod.set_restart_rate(0);
}

#define SPECIALIZE_ADDER(PROTO, func)           \
	template<>                              \
	void add_obj_to_state(draiosproto::k8s_state& state, const PROTO& obj)	\
	{                                       \
		auto*	p = state.func();       \
		p->CopyFrom(obj);               \
	}

SPECIALIZE_ADDER(draiosproto::k8s_pod, add_pods);
SPECIALIZE_ADDER(draiosproto::k8s_node, add_nodes);
SPECIALIZE_ADDER(draiosproto::k8s_replica_set, add_replica_sets);
SPECIALIZE_ADDER(draiosproto::k8s_deployment, add_deployments);
SPECIALIZE_ADDER(draiosproto::k8s_hpa, add_hpas);
SPECIALIZE_ADDER(draiosproto::k8s_service, add_services);
SPECIALIZE_ADDER(draiosproto::k8s_namespace, add_namespaces);

}  // namespace details
}  // namespace test
