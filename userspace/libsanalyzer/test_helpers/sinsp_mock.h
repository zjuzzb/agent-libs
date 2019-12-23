#pragma once

#include "sinsp_evt_wrapper.h"
#include "container_builder.h"
#include "event_builder.h"
#include "thread_builder.h"
#include <sinsp.h>

namespace test_helpers {

/**
 * This is a mock of the sysdig sinsp class. The purpose is to allow the
 * caller to create fake threads, containers and events.
 *
 * Note that this was created years after sinsp was written and the
 * internals are bolted-on in places but effort should be made to keep the
 * sinsp_mock interface as simple as possible.
 */
class sinsp_mock : public sinsp
{
public:
	sinsp_mock();
	~sinsp_mock() override;

	/**
	 * @return a thread_builder that commits into this class
	 */
	thread_builder build_thread();

	/**
	 * @return a container_builder that commits into this class
	 */
	container_builder build_container(sinsp_threadinfo& tinfo);

	/**
	 * @return an event_builder that commits into this class
	 */
	event_builder build_event(sinsp_threadinfo& tinfo);

	// implement sinsp
	void open(uint32_t timeout_ms = SCAP_TIMEOUT_MS) override;
	int32_t next(OUT sinsp_evt **evt) override;
private:
	void commit_thread(sinsp_threadinfo *thread_info);
	void commit_container(const sinsp_container_info::ptr_t&, sinsp_threadinfo& tinfo);
	void commit_event(const sinsp_evt_wrapper::ptr& event, unsigned int count);

	struct event_and_count
	{
		event_and_count(const sinsp_evt_wrapper::ptr& e, unsigned int c) :
			event(e),
			count(c)
		{}

		sinsp_evt_wrapper::ptr event;
		unsigned int count;
	};
	std::deque<event_and_count> m_events;
	std::vector<event_and_count> m_completed_events;
	scap_machine_info m_mock_machine_info;
	sinsp_network_interfaces m_network_interfaces;
	scap_stats m_scap_stats;

	// implement sinsp
	void get_capture_stats(scap_stats *stats) const override;
	int /*SCAP_X*/ dynamic_snaplen(bool value) override { return SCAP_SUCCESS; }

	using thread_info_ptr = std::unique_ptr<const sinsp_threadinfo>;
	std::list<thread_info_ptr> m_temporary_threadinfo_list;
};

}
