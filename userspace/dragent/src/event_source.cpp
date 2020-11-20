#include "event_source.h"

event_source::event_source()
	: m_listeners()
{
}

void event_source::register_event_listener(std::shared_ptr<event_listener> listener)
{
	std::lock_guard<std::mutex> lock(m_listener_lock);
	m_listeners.insert(listener);
}

std::set<std::shared_ptr<event_listener>> event_source::get_event_listeners()
{
	std::lock_guard<std::mutex> lock(m_listener_lock);
	return m_listeners;
}

void event_source::process_event(agent_event* evt)
{
	std::lock_guard<std::mutex> lock(m_listener_lock);
	for (auto& listener : m_listeners)
	{
		listener->process_event(evt);
	}
}
