#pragma once

#include <event.h>
#include <functional>

namespace test_helpers
{

/**
 * Easy way to create events in unit test. The constructor sets
 * defaults for all of the events values and this class has
 * setters for the other values.  Each setter returns *this so
 * that the setters can be called in sequence.
 *
 * This is meant to be constructed by a test_helper that sets
 * the commit delegate before passing the event_builder back to
 * the client.
 *
 * Usage:
 * event_builder().cpuid(10).count(2).commit()
 */
class event_builder
{
public:

	/**
	 * ctor without commit
	 */
	event_builder() :
	   m_event(new sinsp_evt_wrapper())
	{
		set_defaults();
	}

	using commit_delegate = std::function<void(const sinsp_evt_wrapper::ptr& event, unsigned int count)>;
	/**
	 * ctor with a commit delegate where the generated events are
	 * sent to a consumer.
	 */
	event_builder(const commit_delegate& delegate) :
	   m_commit(delegate),
	   m_event(new sinsp_evt_wrapper())
	{
		set_defaults();
	}

	/**
	 * @returns the event with default values except for fields that
	 *        were overridden
	 */
	sinsp_evt_wrapper::ptr generate()
	{
		// If time isn't set, the default is now
		if(!m_event->get()->m_pevt->ts)
		{
			m_event->get()->m_pevt->ts = sinsp_utils::get_current_time_ns();
		}

		return m_event;
	}

	/**
	 * Set the number of times that this system call exists. This is
	 * only applicable if using 'commit'
	 */
	event_builder& count(unsigned int value)
	{
		if(value)
		{
			m_count = value;
		}
		return *this;
	}

	/**
	 * Set the type of system call
	 * @return the builder
	 */
	event_builder& type(ppm_event_type value)
	{
		m_event->get()->m_pevt->type = value;
		return *this;
	}

	/**
	 * Set the time stamp
	 * @return the builder
	 */
	event_builder& ts(uint64_t value)
	{
		m_event->get()->m_pevt->ts = value;
		return *this;
	}

	/**
	 * Set the cpuid
	 * @return the builder
	 */
	event_builder& cpuid(uint16_t value)
	{
		m_event->get()->m_cpuid = value;
		return *this;
	}

	/**
	 * Set the thread id (different from the pid)
	 */
	event_builder& tid(int64_t value)
	{
		m_event->tid(value);
		return *this;
	}

	/**
	 * @return the thread id
	 */
	int64_t tid()
	{
		return m_event->tid();
	}

	/**
	 * Generate this event and pass it to the consumer along with
	 * the count
	 */
	void commit()
	{
		sinsp_evt_wrapper::ptr event = generate();
		m_commit(event, m_count);
	}
private:

	void set_defaults()
	{
		m_event->tid(0x7777555577775555);

		m_event->get()->m_cpuid = 0x2222;

		// SCAP_EVT
		scap_evt& evt = *m_event->get()->m_pevt;
		// If ts isn't set by the client, then this will be set in generate
		evt.ts = 0;
		evt.len = 0;
		evt.type = PPME_SYSCALL_OPEN_E;
	}

	commit_delegate m_commit;
	sinsp_evt_wrapper::ptr m_event;
	unsigned int m_count = 1;

};

}
