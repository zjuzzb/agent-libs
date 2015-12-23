//
// mesos_event_data.cpp
//


#include "mesos_event_data.h"

mesos_event_data::mesos_event_data(mesos_component::type component, const char* data, int len):
	m_component(component),
	m_data(data, len)
{
}

mesos_event_data::mesos_event_data(const mesos_event_data& other):
	m_component(other.m_component),
	m_data(other.m_data)
{
}

mesos_event_data::mesos_event_data(mesos_event_data&& other):
	m_component(std::move(other.m_component)),
	m_data(std::move(other.m_data))
{
}

mesos_event_data& mesos_event_data::operator=(mesos_event_data&& other)
{
	if(this != &other)
	{
		m_component = other.m_component;
		m_data = other.m_data;
	}
	return *this;
}
