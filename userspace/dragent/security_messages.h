# pragma once

#include "Poco/Mutex.h"

#include "draios.pb.h"

// This is a wrapper around a list of policy event messages that
// provides synchronized access. It performs a role similar to the
// protocol_queue used by metrics messages, but always combines sets
// of policy event messages together.
//
// Another difference from protocol_queue is that this class does not
// have any semaphore to allow for waiting on a condition. get()
// simply checks for queued events and returns them + true or returns
// false.

class synchronized_policy_events
{
public:

	synchronized_policy_events(uint32_t max_queued_events);
	virtual ~synchronized_policy_events();

	bool put(draiosproto::policy_events &events);
	bool get(draiosproto::policy_events &events);

private:
	uint32_t m_max_queued_events;
	draiosproto::policy_events m_events;
	Poco::Mutex m_mutex;
};
