//
// k8s_component.h
//
// kubernetes components (nodes, namespaces, pods, replication controllers, services)
// abstraction
//

#pragma once

#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <vector>
#include <map>
#include <unordered_map>

typedef std::pair<std::string, std::string> mesos_pair_t;
typedef std::vector<mesos_pair_t>           mesos_pair_list;

// 
// component
//

class mesos_component
{
public:
	enum type
	{
		MESOS_FRAMEWORK,
		MESOS_TASK,
		MESOS_SLAVE,
		//MESOS_MARATHON
	};

	typedef std::pair<type, std::string> component_pair;
	typedef std::map<type, std::string> component_map;
	static const component_map list;

	mesos_component() = delete;

	mesos_component(const std::string& name, const std::string& uid);

	const std::string& get_name() const;

	void set_name(const std::string& name);

	const std::string& get_uid() const;

	void set_uid(const std::string& uid);

	k8s_pair_s* get_label(const k8s_pair_s& label);

	const k8s_pair_list& get_labels() const;

	void set_labels(k8s_pair_list&& labels);

	void add_labels(k8s_pair_list&& labels);

	void swap_labels(k8s_pair_list& new_labels);

	void push_label(const k8s_pair_s& label);

	void emplace_label(const k8s_pair_s& label);

	static const std::string& get_name(const component_pair& p);

	static std::string get_name(type t);

	static type get_type(const component_pair& p);

	static type get_type(const std::string& name);

private:
	std::string   m_name;
	std::string   m_uid;
};


//
// framework
//

class mesos_framework : public mesos_component
{
public:
	mesos_framework(const std::string& name, const std::string& uid);
};


//
// task
//

class mesos_task : public mesos_component
{
public:
	typedef std::vector<std::string> host_ip_list;

	mesos_task(const std::string& name, const std::string& uid);
	
private:
};


//
// slave
//

class mesos_slave : public mesos_component
{
public:
	mesos_slave(const std::string& name, const std::string& uid);

private:
};

typedef std::vector<mesos_framework> mesos_frameworks;
typedef std::vector<mesos_task>      mesos_tasks;
typedef std::vector<mesos_slave>     mesos_slaves;

//
// component
//

inline const std::string& mesos_component::get_name() const
{
	return m_name;
}

inline void mesos_component::set_name(const std::string& name)
{
	m_name = name;
}

inline const std::string& mesos_component::get_uid() const{
	
	return m_uid;
}

inline void mesos_component::set_uid(const std::string& uid)
{
	m_uid = uid;
}

inline const k8s_pair_list& k8s_component::get_labels() const
{
	return m_labels;
}

inline void k8s_component::set_labels(k8s_pair_list&& labels)
{
	m_labels = std::move(labels);
}

inline void k8s_component::swap_labels(k8s_pair_list& new_labels)
{
	m_labels.swap(new_labels);
}

inline void k8s_component::push_label(const k8s_pair_s& label)
{
	m_labels.push_back(label);
}

inline void k8s_component::emplace_label(const k8s_pair_s& label)
{
	m_labels.emplace_back(label);
}

inline const std::string& k8s_component::get_name(const component_pair& p)
{
	return p.second;
}

inline k8s_component::type k8s_component::get_type(const component_pair& p)
{
	return p.first;
}
