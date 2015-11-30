//
// k8s_state.cpp
//

#include "mesos_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// state
//

mesos_state_t::mesos_state_t(bool is_captured) : m_is_captured(is_captured)
{
}

const mesos_task& mesos_state_t::get_task(const std::string& uid) const
{
	for(const auto& framework : get_frameworks())
	{
		for(const auto& task : framework.get_tasks())
		{
			if(task.first == uid)
			{
				return task.second;
			}
		}
	}
	throw sinsp_exception("Task not found: " + uid);
}

mesos_task& mesos_state_t::get_task(const std::string& uid)
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
