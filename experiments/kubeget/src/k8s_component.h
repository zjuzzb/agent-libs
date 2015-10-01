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

	typedef std::map<type, std::string>         component_map;

	k8s_component(const std::string& name, const std::string& uid, const std::string& ns = "") ;

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
	// namespaces
	const std::vector<k8s_ns_s>& get_namespaces() const;

	void push_namespace(const k8s_ns_s& ns);

	void emplace_namespace(k8s_ns_s&& ns);

	// nodes
	const std::vector<k8s_node_s>& get_nodes() const;

	void push_node(const k8s_node_s& node);

	void emplace_node(k8s_node_s&& node);
	
	// pods
	const std::vector<k8s_pod_s>& get_pods() const;

	void push_pod(const k8s_pod_s& pod);

	void emplace_pod(k8s_pod_s&& pod);

	// replication controllers
	const std::vector<k8s_rc_s>& get_rcs() const;

	void push_rc(const k8s_rc_s& rc);

	void emplace_rc(k8s_rc_s&& rc);

	// services
	const std::vector<k8s_service_s>& get_services() const;

	void push_service(const k8s_service_s& service);

	void emplace_service(k8s_service_s&& service);

	void emplace_item(k8s_component::type t, const std::string& name, k8s_pair_s&& item);

	void add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns);
	
	void set_last_pod_node_name(const std::string& name);
	
	void set_last_pod_host_ip(const std::string& host_ip);
	
	void set_last_pod_internal_ip(const std::string& internal_ip);

	void add_last_node_ip(std::string&& ip);

	void add_last_pod_container_id(std::string&& container_id);

private:
	std::vector<k8s_ns_s>      m_nss;
	std::vector<k8s_node_s>    m_nodes;
	std::vector<k8s_pod_s>     m_pods;
	std::vector<k8s_rc_s>      m_rcs;
	std::vector<k8s_service_s> m_services;
};


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
	m_nodes.back().emplace_host_ip(std::forward<std::string>(ip));
}

inline void k8s_state_s::add_last_pod_container_id(std::string&& container_id)
{
	m_pods.back().emplace_container_id(std::forward<std::string>(container_id));
}
