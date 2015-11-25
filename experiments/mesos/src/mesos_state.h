//
// mesos_state.h
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

class mesos_state
{
public:
	mesos_state(bool is_captured = false);

	//
	// frameworks
	//

	const mesos_frameworks& get_frameworks() const;

	mesos_frameworks& get_frameworks();

	void push_framework(const mesos_framework& ns);

	void emplace_framework(mesos_framework&& ns);

	//
	// tasks
	//

	const mesos_tasks& get_tasks() const;

	mesos_tasks& get_tasks();

	mesos_task* get_task(const std::string& uid);

	void push_task(const mesos_task& task);

	void emplace_task(mesos_task&& task);

	//
	// slaves
	//

	const mesos_slaves& get_slaves() const;

	mesos_slaves& get_slaves();

	void push_slave(const mesos_slave& slave);

	void emplace_slave(mesos_slave&& slave);

	void update_slave(mesos_slave& slave, const Json::Value& item, bool reset);

	bool has_slave(mesos_slave& slave);

private:

	mesos_frameworks m_frameworks;
	mesos_tasks      m_tasks;
	mesos_slaves     m_slaves;
	bool             m_is_captured;
};

// frameworks
inline const mesos_frameworks& mesos_state::get_frameworks() const
{
	return m_frameworks;
}

inline mesos_frameworks& mesos_state::get_frameworks()
{
	return m_frameworks;
}

inline void mesos_state::push_framework(const mesos_framework& ns)
{
	m_frameworks.push_back(ns);
}

inline void mesos_state::emplace_framework(mesos_framework&& ns)
{
	m_frameworks.emplace_back(std::move(ns));
}

// tasks
inline const mesos_tasks& mesos_state::get_tasks() const
{
	return m_tasks;
}

inline mesos_tasks& mesos_state::get_tasks()
{
	return m_tasks;
}

inline void mesos_state::push_task(const mesos_task& task)
{
	m_tasks.push_back(task);
}

inline void mesos_state::emplace_task(mesos_task&& task)
{
	m_tasks.emplace_back(std::move(task));
}

// slaves
inline const mesos_slaves& mesos_state::get_slaves() const
{
	return m_slaves;
}

inline mesos_slaves& mesos_state::get_slaves()
{
	return m_slaves;
}

inline void mesos_state::push_slave(const mesos_slave& pod)
{
	m_slaves.push_back(pod);
}

inline void mesos_state::emplace_slave(mesos_slave&& pod)
{
	m_slaves.emplace_back(std::move(pod));
}
