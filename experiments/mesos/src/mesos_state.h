//
// mesos_state_t.h
//
// mesos state abstraction
//

#pragma once

#include "mesos_component.h"
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

	std::shared_ptr<mesos_task> get_task(const std::string& uid);

	void add_or_replace_task(mesos_framework& framework, std::shared_ptr<mesos_task> task);

	//
	// slaves
	//

private:

	mesos_frameworks m_frameworks;
	bool             m_is_captured;
};

// frameworks
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

// slaves
