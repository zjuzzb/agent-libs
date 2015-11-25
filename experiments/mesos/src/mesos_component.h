//
// mesos_component.h
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

	mesos_component(type t, const std::string& name, const std::string& uid);

	mesos_component(const mesos_component& other);

	mesos_component(mesos_component&& other);

	mesos_component& operator=(const mesos_component& other);

	mesos_component& operator=(const mesos_component&& other);

	const std::string& get_name() const;

	void set_name(const std::string& name);

	const std::string& get_uid() const;

	void set_uid(const std::string& uid);

	mesos_pair_t* get_label(const mesos_pair_t& label);

	const mesos_pair_list& get_labels() const;

	void set_labels(mesos_pair_list&& labels);

	void add_labels(mesos_pair_list&& labels);

	void swap_labels(mesos_pair_list& new_labels);

	void push_label(const mesos_pair_t& label);

	void emplace_label(const mesos_pair_t& label);

	static const std::string& get_name(const component_pair& p);

	static std::string get_name(type t);

	static type get_type(const component_pair& p);

	static type get_type(const std::string& name);

private:
	type            m_type;
	std::string     m_name;
	std::string     m_uid;
	mesos_pair_list m_labels;
};


class mesos_framework;

//
// task
//

class mesos_task : public mesos_component
{
public:
	typedef std::vector<std::string> host_ip_list;

	mesos_task(mesos_framework& framework, const std::string& name, const std::string& uid);

	mesos_task(const mesos_task& other);

	mesos_task(mesos_task&& other);

	mesos_task& operator=(const mesos_task& other);

	mesos_task& operator=(const mesos_task&& other);

	const mesos_framework& get_framework() const;

private:
	mesos_framework* m_framework;
};

//
// framework
//

class mesos_framework : public mesos_component
{
public:
	typedef std::unordered_map<std::string, mesos_task> task_map;

	mesos_framework(const std::string& name, const std::string& uid);

	~mesos_framework();

	bool has_task(const std::string& uid) const;

	void add_or_replace_task(const mesos_task& task);

	void remove_task(const std::string& uid);

	const task_map& get_tasks() const;

private:
	task_map m_tasks;
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

inline const mesos_pair_list& mesos_component::get_labels() const
{
	return m_labels;
}

inline void mesos_component::set_labels(mesos_pair_list&& labels)
{
	m_labels = std::move(labels);
}

inline void mesos_component::swap_labels(mesos_pair_list& new_labels)
{
	m_labels.swap(new_labels);
}

inline void mesos_component::push_label(const mesos_pair_t& label)
{
	m_labels.push_back(label);
}

inline void mesos_component::emplace_label(const mesos_pair_t& label)
{
	m_labels.emplace_back(label);
}

inline const std::string& mesos_component::get_name(const component_pair& p)
{
	return p.second;
}

inline mesos_component::type mesos_component::get_type(const component_pair& p)
{
	return p.first;
}

//
// task
//

inline const mesos_framework& mesos_task::get_framework() const
{
	return *m_framework;
}

//
// framework
//

inline bool mesos_framework::has_task(const std::string& uid) const
{
	return m_tasks.find(uid) != m_tasks.end();
}
