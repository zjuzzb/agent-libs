#pragma once

#include <sinsp.h>
#include "sinsp_evt_wrapper.h"
#include "event_builder.h"

namespace test_helpers {

/**
 * This is a mock of the sysdig sinsp class. The purpose is to
 * allow the caller to create fake events that will then be
 * passed into the analyzer when next is called.
 * This is generally accomplished by overriding calls which
 * normally call down into scap and return fake data instead.
 */
class sinsp_mock : public sinsp
{
public:
	sinsp_mock();
	~sinsp_mock() override;

	/**
	 * @return an event_builder that commits into this class
	 */
	event_builder build_event();

	// implement sinsp
	void open(uint32_t timeout_ms = SCAP_TIMEOUT_MS) override;
	int32_t next(OUT sinsp_evt **evt) override;
private:
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
	void get_capture_stats(scap_stats *stats) override;
};

}
