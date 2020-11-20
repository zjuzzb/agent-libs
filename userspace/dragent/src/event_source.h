#pragma once

#include <mutex>
#include <memory>
#include <set>

// we're trying to contain the dependencies on sinsp as much as possible.
// but need this define until we've defined an appropriate agent struct
class sinsp_evt;
typedef sinsp_evt agent_event;

/**
 * the abstraction that one needs to inherit from if they want callbacks for events
 */
class event_listener
{
public:
	virtual ~event_listener() {}

	virtual void process_event(agent_event* evt) = 0;
};

/**
 * An abstraction of an event source that can be used with whatever event driver. It's
 * generally expected to be an instance of sinsp or sinsp test, but allows us to decouple
 * sinsp from the agent(ino|one)? proper
 */
class event_source
{
public:
	event_source();
	virtual ~event_source() {}

	/**
	 * invoke to get callbacks of all events found by this event source.
	 *
	 * There is no guarantee about the ordering of the callbacks across various listeners
	 */
	void register_event_listener(std::shared_ptr<event_listener> listener);

	/**
	 * returns the current event listeners
	 */
	std::set<std::shared_ptr<event_listener>> get_event_listeners();

	/**
	 * invoke to start event collection
	 */
	virtual void start() = 0;

protected:
	/**
	 * should only be invoked by derived subclass when there is an event that
	 * needs to be dealt with
	 */
	void process_event(agent_event* evt);

private:
	std::mutex m_listener_lock;
	std::set<std::shared_ptr<event_listener>> m_listeners;
};
