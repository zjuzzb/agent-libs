//
// k8s_component.h
//
// kubernetes components (nodes, namespaces, pods, replication controllers, services)
// abstraction
//

#pragma once

#include <vector>
#include <map>

typedef std::pair<std::string, std::string> k8s_pair_s;
typedef std::vector<k8s_pair_s>             k8s_pair_list;

// 
// component
//

class k8s_component
{
public:
	enum type
	{
		K8S_NODES,
		K8S_NAMESPACES,
		K8S_PODS,
		K8S_REPLICATIONCONTROLLERS,
		K8S_SERVICES
	};

	typedef std::map<type, std::string> component_map;
	static const component_map list;

	k8s_component() = delete;

	k8s_component(const std::string& name, const std::string& uid, const std::string& ns = "");

	const std::string& get_name() const;
	
	void set_name(const std::string& name);

	const std::string& get_uid() const;
	
	void set_uid(const std::string& uid);

	const std::string& get_namespace() const;
	
	void set_namespace(const std::string& ns);

	const k8s_pair_list& get_labels() const;

	void push_label(const k8s_pair_s& label);

	void emplace_label(const k8s_pair_s& label);

	const k8s_pair_list& get_selectors() const;

	void push_selector(const k8s_pair_s& selector);

	void emplace_selector(k8s_pair_s&& selector);

private:
	std::string   m_name;
	std::string   m_uid;
	std::string   m_ns;
	k8s_pair_list m_labels;
	k8s_pair_list m_selectors;
	
	friend class k8s_state_s;
};


//
// namespace
//

class k8s_ns_s : public k8s_component
{
public:
	k8s_ns_s(const std::string& name, const std::string& uid, const std::string& ns = "");
};


//
// node
//

class k8s_node_s : public k8s_component
{
public:
	k8s_node_s(const std::string& name, const std::string& uid, const std::string& ns = "");
	
	const std::vector<std::string>& get_host_ips() const;

	void push_host_ip(const std::string& host_ip);

	void emplace_host_ip(std::string&& host_ip);

private:
	std::vector<std::string> host_ips;
};


//
// pod
//

class k8s_pod_s : public k8s_component
{
public:
	k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns = "");
	
	const std::vector<std::string>& get_container_ids() const;

	void push_container_id(const std::string& container_id);

	void emplace_container_id(std::string&& container_id);

	const std::string& get_node_name() const;
	
	void set_node_name(const std::string& name);

	const std::string& get_host_ip() const;
	
	void set_host_ip(const std::string& host_ip);

	const std::string& get_internal_ip() const;
	
	void set_internal_ip(const std::string& internal_ip);

private:
	std::vector<std::string> m_container_ids;
	std::string              m_node_name;
	std::string              m_host_ip;
	std::string              m_internal_ip;
};


//
// replication controller
//

class k8s_rc_s : public k8s_component
{
public:
	k8s_rc_s(const std::string& name, const std::string& uid, const std::string& ns = "");
};


//
// service
//

class k8s_service_s : public k8s_component
{
public:
	k8s_service_s(const std::string& name, const std::string& uid, const std::string& ns = "");
};


//
// state
//

class k8s_state_s
{
public:
	k8s_state_s();

	//
	// namespaces
	//

	const std::vector<k8s_ns_s>& get_namespaces() const;
	std::vector<k8s_ns_s>& get_namespaces();

	void push_namespace(const k8s_ns_s& ns);

	void emplace_namespace(k8s_ns_s&& ns);

	//
	// nodes
	//

	const std::vector<k8s_node_s>& get_nodes() const;
	std::vector<k8s_node_s>& get_nodes();

	void push_node(const k8s_node_s& node);

	void emplace_node(k8s_node_s&& node);
	
	//
	// pods
	//

	const std::vector<k8s_pod_s>& get_pods() const;
	std::vector<k8s_pod_s>& get_pods();

	void push_pod(const k8s_pod_s& pod);

	void emplace_pod(k8s_pod_s&& pod);

	//
	// replication controllers
	//

	const std::vector<k8s_rc_s>& get_rcs() const;
	std::vector<k8s_rc_s>& get_rcs();

	void push_rc(const k8s_rc_s& rc);

	void emplace_rc(k8s_rc_s&& rc);

	//
	// services
	//

	const std::vector<k8s_service_s>& get_services() const;
	std::vector<k8s_service_s>& get_services();

	void push_service(const k8s_service_s& service);

	void emplace_service(k8s_service_s&& service);

	//
	// general
	//

	void emplace_item(k8s_component::type t, const std::string& name, k8s_pair_s&& item);

	k8s_component& add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns);
	
	void set_last_pod_node_name(const std::string& name);
	
	void set_last_pod_host_ip(const std::string& host_ip);
	
	void set_last_pod_internal_ip(const std::string& internal_ip);

	void add_last_node_ip(std::string&& ip);

	void add_last_pod_container_id(std::string&& container_id);

	// Returns true if component exists, false otherwise.
	template <typename C>
	bool has(const C& container, const std::string& uid) const
	{
		for (auto& comp : container)
		{
			if (uid == comp.get_uid())
			{
				return true;
			}
		}
		return false;
	}

	typedef std::vector<k8s_ns_s>      namespaces;
	typedef std::vector<k8s_node_s>    nodes;
	typedef std::vector<k8s_pod_s>     pods;
	typedef std::vector<k8s_rc_s>      controllers;
	typedef std::vector<k8s_service_s> services;

	// Returns the reference to existing component, if it exists.
	// If component does not exist, it emplaces it to the back of the
	// container and returns the reference of the added component.
	template <typename C, typename T>
	T& get(C& container, const std::string& name, const std::string& uid, const std::string& ns)
	{
		for (auto& comp : container)
		{
			if (comp.get_uid() == uid)
			{
				return comp;
			}
		}
		container.emplace_back(T(name, uid, ns));
		return container.back();
	}

private:
	namespaces  m_namespaces;
	nodes       m_nodes;
	pods        m_pods;
	controllers m_controllers;
	services    m_services;
};

//
// component
//

inline const std::string& k8s_component::get_name() const
{
	return m_name;
}

inline void k8s_component::set_name(const std::string& name)
{
	m_name = name;
}

inline const std::string& k8s_component::get_uid() const{
	
	return m_uid;
}

inline void k8s_component::set_uid(const std::string& uid)
{
	m_uid = uid;
}

inline const std::string& k8s_component::get_namespace() const
{
	return m_ns;
}

inline void k8s_component::set_namespace(const std::string& ns)
{
	m_ns = ns;
}

inline const k8s_pair_list& k8s_component::get_labels() const
{
	return m_labels;
}

inline void k8s_component::push_label(const k8s_pair_s& label)
{
	m_labels.push_back(label);
}

inline void k8s_component::emplace_label(const k8s_pair_s& label)
{
	m_labels.emplace_back(label);
}

inline const k8s_pair_list& k8s_component::get_selectors() const
{
	return m_selectors;
}

inline void k8s_component::push_selector(const k8s_pair_s& selector)
{
	m_selectors.push_back(selector);
}

inline void k8s_component::emplace_selector(k8s_pair_s&& selector)
{
	m_selectors.emplace_back(std::move(selector));
}


//
// node
//

inline const std::vector<std::string>& k8s_node_s::get_host_ips() const
{
	return host_ips;
}

inline void k8s_node_s::push_host_ip(const std::string& host_ip)
{
	host_ips.push_back(host_ip);
}

inline void k8s_node_s::emplace_host_ip(std::string&& host_ip)
{
	host_ips.emplace_back(std::move(host_ip));
}


//
// pod 
//

inline const std::vector<std::string>& k8s_pod_s::get_container_ids() const
{
	return m_container_ids;
}

inline void k8s_pod_s::push_container_id(const std::string& container_id)
{
	m_container_ids.push_back(container_id);
}

inline void k8s_pod_s::emplace_container_id(std::string&& container_id)
{
	m_container_ids.emplace_back(std::move(container_id));
}

inline const std::string& k8s_pod_s::get_node_name() const
{
	return m_node_name;
}

inline void k8s_pod_s::set_node_name(const std::string& name)
{
	m_node_name = name;
}

inline const std::string& k8s_pod_s::get_host_ip() const
{
	return m_host_ip;
}

inline void k8s_pod_s::set_host_ip(const std::string& host_ip)
{
	m_host_ip = host_ip;
}

inline const std::string& k8s_pod_s::get_internal_ip() const
{
	return m_internal_ip;
}

inline void k8s_pod_s::set_internal_ip(const std::string& internal_ip)
{
	m_internal_ip = internal_ip;
}


//
// state
//

// namespaces
inline const std::vector<k8s_ns_s>& k8s_state_s::get_namespaces() const
{
	return m_namespaces;
}

inline std::vector<k8s_ns_s>& k8s_state_s::get_namespaces()
{
	return m_namespaces;
}

inline void k8s_state_s::push_namespace(const k8s_ns_s& ns)
{
	m_namespaces.push_back(ns);
}

inline void k8s_state_s::emplace_namespace(k8s_ns_s&& ns)
{
	m_namespaces.emplace_back(std::move(ns));
}

// nodes
inline const std::vector<k8s_node_s>& k8s_state_s::get_nodes() const
{
	return m_nodes;
}

inline std::vector<k8s_node_s>& k8s_state_s::get_nodes()
{
	return m_nodes;
}

inline void k8s_state_s::push_node(const k8s_node_s& node)
{
	m_nodes.push_back(node);
}

inline void k8s_state_s::emplace_node(k8s_node_s&& node)
{
	m_nodes.emplace_back(std::move(node));
}

// pods
inline const std::vector<k8s_pod_s>& k8s_state_s::get_pods() const
{
	return m_pods;
}

inline std::vector<k8s_pod_s>& k8s_state_s::get_pods()
{
	return m_pods;
}

inline void k8s_state_s::push_pod(const k8s_pod_s& pod)
{
	m_pods.push_back(pod);
}

inline void k8s_state_s::emplace_pod(k8s_pod_s&& pod)
{
	m_pods.emplace_back(std::move(pod));
}

// replication controllers
inline const std::vector<k8s_rc_s>& k8s_state_s::get_rcs() const
{
	return m_controllers;
}

inline std::vector<k8s_rc_s>& k8s_state_s::get_rcs()
{
	return m_controllers;
}

inline void k8s_state_s::push_rc(const k8s_rc_s& rc)
{
	m_controllers.push_back(rc);
}

inline void k8s_state_s::emplace_rc(k8s_rc_s&& rc)
{
	m_controllers.emplace_back(std::move(rc));
}

// services
inline const std::vector<k8s_service_s>& k8s_state_s::get_services() const
{
	return m_services;
}

inline std::vector<k8s_service_s>& k8s_state_s::get_services()
{
	return m_services;
}

inline void k8s_state_s::push_service(const k8s_service_s& service)
{
	m_services.push_back(service);
}

inline void k8s_state_s::emplace_service(k8s_service_s&& service)
{
	m_services.emplace_back(std::move(service));
}

// general
inline void k8s_state_s::set_last_pod_node_name(const std::string& name)
{
	m_pods.back().set_node_name(name);
}

inline void k8s_state_s::set_last_pod_host_ip(const std::string& host_ip)
{
	m_pods.back().set_host_ip(host_ip);
}

inline void k8s_state_s::set_last_pod_internal_ip(const std::string& internal_ip)
{
	m_pods.back().set_internal_ip(internal_ip);
}

inline void k8s_state_s::add_last_node_ip(std::string&& ip)
{
	m_nodes.back().emplace_host_ip(std::move(ip));
}

inline void k8s_state_s::add_last_pod_container_id(std::string&& container_id)
{
	m_pods.back().emplace_container_id(std::move(container_id));
}
