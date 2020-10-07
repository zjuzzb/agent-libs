#pragma once
#include "draios.pb.h"

#include <type_traits>

// A collection of template free functions and some full specialization
// They are only ment to be used by infra_util class for fully specialize
// some of his methods
namespace test
{
namespace details
{
template<typename T>
void add_obj_to_state(draiosproto::k8s_state& state, const T& obj);

template<typename T>
void set_namespace(T& obj, const std::string& ns)
{
	obj.mutable_common()->set_namespace_(ns);
}

template<>
void set_namespace<draiosproto::k8s_node>(draiosproto::k8s_node& obj, const std::string& ns);

template<>
void set_namespace<draiosproto::k8s_namespace>(draiosproto::k8s_namespace& obj,
                                               const std::string& ns);

template<typename T>
void set_node(T& obj, const std::string& node_name)
{
}

template<>
void set_node<draiosproto::k8s_pod>(draiosproto::k8s_pod& pod, const std::string& ns_name);

template<typename T>
void set_restart_rate(T& obj)
{
}

template<>
void set_restart_rate<draiosproto::k8s_pod>(draiosproto::k8s_pod& pod);

template<typename T>
struct parent_remover
{
	using uid_t = std::pair<std::string, std::string>;
	static void remove(T& msg, const uid_t& parent_uid)
	{
		for (auto it = msg.mutable_common()->mutable_parents()->begin();
		     it != msg.mutable_common()->mutable_parents()->end();)
		{
			if (std::make_pair(it->key(), it->value()) == parent_uid)
			{
				it = msg.mutable_common()->mutable_parents()->erase(it);
				break;
			}
			it++;
		}
	}
};

template<typename T>
struct parent_remover<google::protobuf::RepeatedPtrField<T>>
{
	using uid_t = std::pair<std::string, std::string>;
	static void remove(google::protobuf::RepeatedPtrField<T>& repeated_msg, const uid_t& parent_uid)
	{
		for (auto it = repeated_msg.begin(); it != repeated_msg.end(); it++)
		{
			parent_remover<T>::remove(*it, parent_uid);
		}
	}
};

template<>
struct parent_remover<draiosproto::k8s_state>
{
	using uid_t = std::pair<std::string, std::string>;
	static void remove(draiosproto::k8s_state& state, const uid_t& parent)
	{
		parent_remover<std::remove_pointer<decltype(state.mutable_pods())>::type>::remove(
		    *state.mutable_pods(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_hpas())>::type>::remove(
		    *state.mutable_hpas(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_jobs())>::type>::remove(
		    *state.mutable_jobs(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_nodes())>::type>::remove(
		    *state.mutable_nodes(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_services())>::type>::remove(
		    *state.mutable_services(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_daemonsets())>::type>::remove(
		    *state.mutable_daemonsets(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_namespaces())>::type>::remove(
		    *state.mutable_namespaces(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_controllers())>::type>::remove(
		    *state.mutable_controllers(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_deployments())>::type>::remove(
		    *state.mutable_deployments(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_replica_sets())>::type>::remove(
		    *state.mutable_replica_sets(),
		    parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_persistentvolumes())>::type>::
		    remove(*state.mutable_persistentvolumes(), parent);
		parent_remover<std::remove_pointer<decltype(state.mutable_persistentvolumeclaims())>::
		                   type>::remove(*state.mutable_persistentvolumeclaims(), parent);
	}
};

}  // namespace details
}  // namespace test
