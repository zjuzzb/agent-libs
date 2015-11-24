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

	const k8s_tasks& get_tasks() const;

	k8s_tasks& get_tasks();

	mesos_task* get_task(const std::string& uid);

	void push_task(const mesos_task& task);

	void emplace_task(mesos_task&& task);

	//
	// slaves
	//

	const mesos_slaves& get_slaves() const;

	mesos_slaves& get_slaves();

	void push_pod(const mesos_slave& pod);

	void emplace_pod(mesos_slave&& pod);

	void update_pod(mesos_slave& pod, const Json::Value& item, bool reset);

	bool has_pod(mesos_slave& pod);

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
inline const k8s_tasks& mesos_state::get_tasks() const
{
	return m_tasks;
}

inline k8s_tasks& mesos_state::get_tasks()
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

inline void mesos_state::push_pod(const mesos_slave& pod)
{
	m_slaves.push_back(pod);
}

inline void mesos_state::emplace_pod(mesos_slave&& pod)
{
	m_slaves.emplace_back(std::move(pod));
}

inline const mesos_slave::container_id_list& mesos_state::get_pod_container_ids(mesos_slave& pod)
{
	return pod.get_container_ids();
}
