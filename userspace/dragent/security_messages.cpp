#include "logger.h"
#include "security_messages.h"

using namespace Poco;

synchronized_policy_events::synchronized_policy_events(uint32_t max_queued_events)
	: m_max_queued_events(max_queued_events)
{
}

synchronized_policy_events::~synchronized_policy_events()
{
}

bool synchronized_policy_events::put(draiosproto::policy_events &events)
{
	Mutex::ScopedLock lock(m_mutex);

	if((uint32_t) (m_events.events_size() + events.events_size()) > m_max_queued_events)
	{
		return false;
	}

	m_events.MergeFrom(events);

	return true;
}

bool synchronized_policy_events::get(draiosproto::policy_events &events)
{
	Mutex::ScopedLock lock(m_mutex);

	if(m_events.events_size() == 0)
	{
		return false;
	}

	// Clear events, set its machine id/customer id from
	// m_events, and then swap them.
	events.Clear();
	events.set_machine_id(m_events.machine_id());
	events.set_customer_id(m_events.customer_id());
	m_events.Swap(&events);

	return true;
}
