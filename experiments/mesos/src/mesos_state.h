//
// mesos_state_t.h
//
// mesos state abstraction
//

#pragma once

#include "mesos_component.h"
#include "m6n_component.h"
#include "json/json.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <vector>
#include <map>
#include <unordered_map>

//
// state
//

class mesos_state_t
{
public:
	mesos_state_t(bool is_captured = false);

	//
	// frameworks
	//

	const mesos_frameworks& get_frameworks() const;

	mesos_frameworks& get_frameworks();

	const mesos_framework& get_framework(const std::string& framework_uid) const;

	mesos_framework& get_framework(const std::string& framework_uid);

	void push_framework(const mesos_framework& framework);

	void emplace_framework(mesos_framework&& framework);

	//
	// tasks
	//

	const mesos_framework::task_map& get_tasks(const std::string& framework_uid) const;

	mesos_framework::task_map& get_tasks(const std::string& framework_uid);

	mesos_framework::task_ptr_t get_task(const std::string& uid);

	void add_or_replace_task(mesos_framework& framework, std::shared_ptr<mesos_task> task);

	//
	// slaves
	//

	//
	// apps
	//

	const m6n_apps& get_apps() const;

	m6n_apps& get_apps();

	m6n_app::ptr_t get_app(const std::string& app_id);

	void add_or_replace_app(m6n_group::app_ptr_t app);

	//
	// groups
	//

	const m6n_groups& get_groups() const;

	m6n_groups& get_groups();

	m6n_group::ptr_t get_group(const std::string& group_id);

	m6n_group::ptr_t add_or_replace_group(m6n_group::ptr_t group, m6n_group::ptr_t to_group = 0);

private:

	mesos_frameworks m_frameworks;
	m6n_apps         m_apps;
	m6n_groups       m_groups;
	bool             m_is_captured;
};

//
// frameworks
//

inline const mesos_frameworks& mesos_state_t::get_frameworks() const
{
	return m_frameworks;
}

inline mesos_frameworks& mesos_state_t::get_frameworks()
{
	return m_frameworks;
}

inline const mesos_framework& mesos_state_t::get_framework(const std::string& framework_uid) const
{
	for(const auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework;
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

inline mesos_framework& mesos_state_t::get_framework(const std::string& framework_uid)
{
	for(auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework;
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

inline void mesos_state_t::push_framework(const mesos_framework& framework)
{
	m_frameworks.push_back(framework);
}

inline void mesos_state_t::emplace_framework(mesos_framework&& framework)
{
	m_frameworks.emplace_back(std::move(framework));
}

inline void mesos_state_t::add_or_replace_task(mesos_framework& framework, std::shared_ptr<mesos_task> task)
{
	framework.add_or_replace_task(task);
}

//
// slaves
//

//
// apps
//

inline const m6n_apps& mesos_state_t::get_apps() const
{
	return m_apps;
}

inline m6n_apps& mesos_state_t::get_apps()
{
	return m_apps;
}

//
// groups
//

inline const m6n_groups& mesos_state_t::get_groups() const
{
	return m_groups;
}

inline m6n_groups& mesos_state_t::get_groups()
{
	return m_groups;
}
