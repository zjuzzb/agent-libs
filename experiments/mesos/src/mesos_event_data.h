//
// mesos_event_data.h
//
// connects and gets the data from mesos_net REST API interface
//
#pragma once

#include "mesos_component.h"


class mesos_event_data
{
public:
	mesos_event_data() = delete;

	mesos_event_data(mesos_component::type component, const char* data, int len);

	mesos_event_data(const mesos_event_data& other);

	mesos_event_data(mesos_event_data&& other);

	mesos_event_data& operator=(mesos_event_data&& other);

	mesos_component::type component() const;

	std::string data() const;

private:
	mesos_component::type m_component;
	std::string         m_data;
};

inline mesos_component::type mesos_event_data::component() const
{
	return m_component;
}
	
inline std::string mesos_event_data::data() const
{
	return m_data;
}