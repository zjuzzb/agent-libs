#pragma once

#include <memory>
#include <event.h>
#include <threadinfo.h>
#include "analyzer_thread.h" /*thread_analyzer_info*/

namespace test_helpers
{

/**
 * Simple class to manage the lifetime of the sinsp_event and
 * all of it's members. This is for convenience so that a
 * pointer to the event can be passed around without worrying
 * about new-ing and free-ing objects.
 */
class sinsp_evt_wrapper
{
public:
	using ptr = std::shared_ptr<sinsp_evt_wrapper>;

	sinsp_evt_wrapper();

	/**
	 * @return a raw pointer to the sinsp_evt.  This is what is
	 *         passed around userspace.
	 */
	sinsp_evt *get();

	/**
	 * Set the thread id
	 */
	void tid(int64_t value)
	{
		m_tid = value;
	}

	/**
	 * @return the thread id
	 */
	int64_t tid()
	{
		return m_tid;
	}

private:
	using sinsp_evt_ptr = std::unique_ptr<sinsp_evt>;
	using scap_evt_ptr = std::unique_ptr<scap_evt>;
	using ppm_event_info_ptr = std::unique_ptr<ppm_event_info>;
	using sinsp_fdinfo_t_ptr = std::unique_ptr<sinsp_fdinfo_t>;
	using thread_analyzer_info_ptr = std::unique_ptr<thread_analyzer_info>;

	sinsp_evt_ptr m_sinsp_event;
	scap_evt_ptr m_scap_event;
	ppm_event_info_ptr m_ppm_event_info;
	sinsp_fdinfo_t_ptr m_sinsp_fdinfo;
	thread_analyzer_info_ptr m_thread_analyzer_info;
	int64_t m_tid;

	// Note that this class does not manage the lifetime of
	// sinsp_threadinfo. This is because this is meant to be used with
	// the sinsp_mock class which has sinsp's thread_manager to manage
	// the lifetime of sinsp_threadinfo. If the use of sinsp_evt_wrapper
	// is extended to other mocks then it might be necessary to revisit.
};

}
