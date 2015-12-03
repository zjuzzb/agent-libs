//
// m6n_component.h
//
// marathon components (groups, apps, tasks)
// abstraction
//

#pragma once

#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos_component.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>

typedef std::pair<std::string, std::string> m6n_pair_t;
typedef std::vector<m6n_pair_t>             m6n_pair_list;

// 
// component
//

class m6n_component
{
public:
	enum type
	{
		M6N_GROUP,
		M6N_APP
	};

	typedef std::pair<type, std::string> component_pair;
	typedef std::map<type, std::string> component_map;
	static const component_map list;

	m6n_component() = delete;

	m6n_component(type t, const std::string& id);

	m6n_component(const m6n_component& other);

	m6n_component(m6n_component&& other);

	m6n_component& operator=(const m6n_component& other);

	m6n_component& operator=(const m6n_component&& other);

	const std::string& get_id() const;

	void set_id(const std::string& name);

	static std::string get_name(type t);

	static type get_type(const std::string& name);

private:
	type        m_type;
	std::string m_id;
};

class m6n_app;

//
// group
//

class m6n_group : public m6n_component
{
public:
	typedef std::shared_ptr<m6n_group> ptr_t;
	typedef std::shared_ptr<m6n_app> app_ptr_t;

	typedef std::unordered_map<std::string, std::shared_ptr<m6n_app>> app_map_t;
	typedef std::map<std::string, std::shared_ptr<m6n_group>> group_map_t;

	m6n_group(const std::string& id);

	m6n_group(const m6n_group& other);

	m6n_group(m6n_group&& other);

	m6n_group& operator=(const m6n_group& other);

	m6n_group& operator=(const m6n_group&& other);

	void add_or_replace_app(std::shared_ptr<m6n_app>);
	void remove_app(const std::string& id);

	void add_or_replace_group(std::shared_ptr<m6n_group>);
	void remove_group(const std::string& id);

	const app_map_t& get_apps() const;
	const group_map_t& get_groups() const;

private:
	app_map_t   m_apps;
	group_map_t m_groups;
};

//
// app
//

class m6n_app : public m6n_component
{
public:
	typedef std::shared_ptr<m6n_app> ptr_t;
	typedef std::vector<mesos_task::ptr_t> task_list_t;

	m6n_app(const std::string& uid);

	~m6n_app();

	void add_or_replace_task(mesos_task::ptr_t ptask);

	const task_list_t& get_tasks() const;

private:
	task_list_t m_tasks;
};

typedef m6n_group::app_map_t m6n_apps;
typedef m6n_group::group_map_t m6n_groups;

//
// component
//

inline const std::string& m6n_component::get_id() const
{
	return m_id;
}

inline void m6n_component::set_id(const std::string& id)
{
	m_id = id;
}


//
// group
//

inline void m6n_group::add_or_replace_app(std::shared_ptr<m6n_app> app)
{
	m_apps.insert({app->get_id(), app});
}

inline void m6n_group::remove_app(const std::string& id)
{
	m_apps.erase(id);
}

inline void m6n_group::add_or_replace_group(std::shared_ptr<m6n_group> group)
{
	m_groups.insert({group->get_id(), group});
}

inline void m6n_group::remove_group(const std::string& id)
{
	m_groups.erase(id);
}

inline const m6n_group::app_map_t& m6n_group::get_apps() const
{
	return m_apps;
}

inline const m6n_group::group_map_t& m6n_group::get_groups() const
{
	return m_groups;
}

//
// app
//

inline const m6n_app::task_list_t& m6n_app::get_tasks() const
{
	return m_tasks;
}
