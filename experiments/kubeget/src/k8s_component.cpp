//
// k8s_component.cpp
//

#include "k8s_component.h"
#include <sstream>

//
// component
//

k8s_component::k8s_component(const std::string& name, const std::string& uid, const std::string& ns) : 
	m_name(name), m_uid(uid), m_ns(ns)
{
}



//
// namespace
//
k8s_ns_s::k8s_ns_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// node
//

k8s_node_s::k8s_node_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// pod 
//

k8s_pod_s::k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// replication controller
//
k8s_rc_s::k8s_rc_s(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}


//
// service
//
k8s_service_s::k8s_service_s(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}


//
// state
//

k8s_state_s::k8s_state_s()
{
}

void k8s_state_s::emplace_item(k8s_component::type t, const std::string& name, k8s_pair_s&& item)
{
	switch (t)
	{
	case k8s_component::K8S_NODES:
		if (name == "labels")
		{
			m_nodes.back().m_labels.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		break;

	case k8s_component::K8S_NAMESPACES:
		if (name == "labels")
		{
			m_nss.back().m_labels.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		break;

	case k8s_component::K8S_PODS:
		if (name == "labels")
		{
			m_pods.back().m_labels.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		break;
	// only controllers and services can have selectors
	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		if (name == "labels")
		{
			m_rcs.back().m_labels.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		else if (name == "selector")
		{
			m_rcs.back().m_selectors.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		break;

	case k8s_component::K8S_SERVICES:
		if (name == "labels")
		{
			m_services.back().m_labels.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		else if (name == "selector")
		{
			m_services.back().m_selectors.emplace_back(std::forward<k8s_pair_s>(item));
			return;
		}
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t) <<
		" or object name " << name;
	throw std::invalid_argument(os.str().c_str());
}

void k8s_state_s::add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns)
{
	switch (component)
	{
		case k8s_component::K8S_NODES:
			m_nodes.emplace_back(k8s_node_s(name, uid, ns));
			break;

		case k8s_component::K8S_NAMESPACES:
			m_nss.emplace_back(k8s_ns_s(name, uid, ns));
			break;

		case k8s_component::K8S_PODS:
			m_pods.emplace_back(k8s_pod_s(name, uid, ns));
			break;

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			m_rcs.emplace_back(k8s_rc_s(name, uid, ns));
			break;

		case k8s_component::K8S_SERVICES:
			m_services.emplace_back(k8s_service_s(name, uid, ns));
			break;

		default:
		{
			std::ostringstream os;
			os << "Unknown component: " << static_cast<int>(component);
			throw std::invalid_argument(os.str());
		}
	}
}



