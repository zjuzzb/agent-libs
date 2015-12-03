//
// k8s_state.cpp
//

#include "mesos_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>
#include <memory>

//
// state
//

mesos_state_t::mesos_state_t(bool is_captured) : m_is_captured(is_captured)
{
}

mesos_framework::task_ptr_t mesos_state_t::get_task(const std::string& uid)
{
	for(auto& framework : get_frameworks())
	{
		for(auto& task : framework.get_tasks())
		{
			if(task.first == uid)
			{
				return task.second;
			}
		}
	}
	throw sinsp_exception("Task not found: " + uid);
}

const mesos_framework::task_map& mesos_state_t::get_tasks(const std::string& framework_uid) const
{
	for(const auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework.get_tasks();
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

mesos_framework::task_map& mesos_state_t::get_tasks(const std::string& framework_uid)
{
	for(auto& framework : m_frameworks)
	{
		if(framework.get_uid() == framework_uid)
		{
			return framework.get_tasks();
		}
	}
	throw sinsp_exception("Framework not found: " + framework_uid);
}

m6n_app::ptr_t mesos_state_t::get_app(const std::string& app_id)
{
	m6n_apps::iterator it = m_apps.find(app_id);
	if(it != m_apps.end())
	{
		return it->second;
	}
	return 0;
}

void mesos_state_t::add_or_replace_app(m6n_group::app_ptr_t app)
{
	std::string id = app->get_id();
	m6n_apps::iterator it = m_apps.find(id);
	if(it != m_apps.end())
	{
		m_apps.erase(it);
	}
	m_apps.insert({id, app});
}

m6n_group::ptr_t mesos_state_t::get_group(const std::string& group_id)
{
	m6n_groups::iterator it = m_groups.find(group_id);
	if(it != m_groups.end())
	{
		return it->second;
	}
	return 0;
}

m6n_group::ptr_t mesos_state_t::add_or_replace_group(m6n_group::ptr_t group, m6n_group::ptr_t to_group)
{
	std::string id = group->get_id();
	if(!to_group) // top level
	{
		m6n_groups::iterator it = m_groups.find(id);
		if(it != m_groups.end())
		{
			m_groups.erase(it);
		}
		m_groups.insert({id, group});
		return group;
	}

	to_group->add_or_replace_group(group);
	return to_group;
}
