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

const std::string& k8s_component::get_name() const
{
	return m_name;
}

void k8s_component::set_name(const std::string& name)
{
	m_name = name;
}

const std::string& k8s_component::get_uid() const{
	
	return m_uid;
}

void k8s_component::set_uid(const std::string& uid)
{
	m_uid = uid;
}

const std::string& k8s_component::get_namespace() const
{
	return m_ns;
}

void k8s_component::set_namespace(const std::string& ns)
{
	m_ns = ns;
}

const k8s_pair_list& k8s_component::get_labels() const
{
	return m_labels;
}

void k8s_component::push_label(const k8s_pair_s& label)
{
	m_labels.push_back(label);
}

void k8s_component::emplace_label(const k8s_pair_s& label)
{
	m_labels.emplace_back(label);
}

const k8s_pair_list& k8s_component::get_selectors() const
{
	return m_selectors;
}

void k8s_component::push_selector(const k8s_pair_s& selector)
{
	m_selectors.push_back(selector);
}

void k8s_component::emplace_selector(k8s_pair_s&& selector)
{
	m_selectors.emplace_back(std::forward<k8s_pair_s>(selector));
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

const std::vector<std::string>& k8s_node_s::get_host_ips() const
{
	return host_ips;
}

void k8s_node_s::push_host_ip(const std::string& host_ip)
{
	host_ips.push_back(host_ip);
}

void k8s_node_s::emplace_host_ip(std::string&& host_ip)
{
	host_ips.emplace_back(std::forward<std::string>(host_ip));
}


//
// pod 
//

k8s_pod_s::k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}

const std::vector<std::string>& k8s_pod_s::get_container_ids() const
{
	return m_container_ids;
}

void k8s_pod_s::push_container_id(const std::string& container_id)
{
	m_container_ids.push_back(container_id);
}

void k8s_pod_s::emplace_container_id(std::string&& container_id)
{
	m_container_ids.emplace_back(std::forward<std::string>(container_id));
}

const std::string& k8s_pod_s::get_node_name() const
{
	return m_node_name;
}

void k8s_pod_s::set_node_name(const std::string& name)
{
	m_node_name = name;
}

const std::string& k8s_pod_s::get_host_ip() const
{
	return m_host_ip;
}

void k8s_pod_s::set_host_ip(const std::string& host_ip)
{
	m_host_ip = host_ip;
}

const std::string& k8s_pod_s::get_internal_ip() const
{
	return m_internal_ip;
}

void k8s_pod_s::set_internal_ip(const std::string& internal_ip)
{
	m_internal_ip = internal_ip;
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

// namespaces
const std::vector<k8s_ns_s>& k8s_state_s::get_namespaces() const
{
	return m_nss;
}

void k8s_state_s::push_namespace(const k8s_ns_s& ns)
{
	m_nss.push_back(ns);
}

void k8s_state_s::emplace_namespace(k8s_ns_s&& ns)
{
	m_nss.emplace_back(std::forward<k8s_ns_s>(ns));
}

// nodes
const std::vector<k8s_node_s>& k8s_state_s::get_nodes() const
{
	return m_nodes;
}

void k8s_state_s::push_node(const k8s_node_s& node)
{
	m_nodes.push_back(node);
}

void k8s_state_s::emplace_node(k8s_node_s&& node)
{
	m_nodes.emplace_back(std::forward<k8s_node_s>(node));
}

// pods
const std::vector<k8s_pod_s>& k8s_state_s::get_pods() const
{
	return m_pods;
}

void k8s_state_s::push_pod(const k8s_pod_s& pod)
{
	m_pods.push_back(pod);
}

void k8s_state_s::emplace_pod(k8s_pod_s&& pod)
{
	m_pods.emplace_back(std::forward<k8s_pod_s>(pod));
}

// replication controllers
const std::vector<k8s_rc_s>& k8s_state_s::get_rcs() const
{
	return m_rcs;
}

void k8s_state_s::push_rc(const k8s_rc_s& rc)
{
	m_rcs.push_back(rc);
}

void k8s_state_s::emplace_rc(k8s_rc_s&& rc)
{
	m_rcs.emplace_back(std::forward<k8s_rc_s>(rc));
}

// services
const std::vector<k8s_service_s>& k8s_state_s::get_services() const
{
	return m_services;
}

void k8s_state_s::push_service(const k8s_service_s& service)
{
	m_services.push_back(service);
}

void k8s_state_s::emplace_service(k8s_service_s&& service)
{
	m_services.emplace_back(std::forward<k8s_service_s>(service));
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



