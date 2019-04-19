#include "sinsp_mock.h"
#include "event_builder.h"
#include "sinsp_evt_wrapper.h"
#include <analyzer.h>

namespace test_helpers
{

sinsp_mock::sinsp_mock() :
	sinsp(),
	m_network_interfaces(this)
{
	m_mock_machine_info.num_cpus = 4;
	m_mock_machine_info.memory_size_bytes = 64ULL * 1024ULL * 1024ULL * 1024ULL; /*64GB*/
	m_mock_machine_info.max_pid = 0x1FFFFFFFFFFFFFFF;
	strcpy(m_mock_machine_info.hostname, "draios-unit-test-host");
}

sinsp_mock::~sinsp_mock()
{
	// The listener can be destroyed before sinsp's thread_manager is destroyed
	// so we disconnect them here to avoid a SEGFAULT.
	m_thread_manager->set_listener(nullptr);
}

event_builder sinsp_mock::build_event()
{
	// Create an event builder that will commit into this class
	return event_builder(std::bind(&sinsp_mock::commit_event,
				       this,
				       std::placeholders::_1,
				       std::placeholders::_2));
}

void sinsp_mock::commit_event(const sinsp_evt_wrapper::ptr& event, unsigned int count)
{
	event->get()->inspector(this);
	m_events.push_back(event_and_count(event, count));
}

void sinsp_mock::open(uint32_t timeout_ms) /*override*/
{
	inject_machine_info(&m_mock_machine_info);
	sinsp_network_interfaces *interfaces = new sinsp_network_interfaces(this);
	*interfaces = m_network_interfaces;
	inject_network_interfaces(interfaces);

	if(m_analyzer) {
		m_analyzer->on_capture_start();
	}
}

int32_t sinsp_mock::next(sinsp_evt **evt) /*override*/
{
	// If the filename is set then we are loading events from an scap file
	// and the baseclass can handle this.
	if(!get_input_filename().empty())
	{
		return sinsp::next(evt);
	}

	if(m_events.empty())
	{
		return SCAP_EOF;
	}

	event_and_count &element = m_events.front();

	*evt = element.event->get();
	--element.count;
	++m_scap_stats.n_evts;

	if(!get_thread(element.event->tid(), false /*do not query os*/, true /*lookup only*/))
	{
		// Thread doesn't exist. Add it.
		// Note that we can't do this in commit_event because we have to
		// wait until after the sinsp_threadtable_listener is initialized.
		sinsp_threadinfo *tinfo = new sinsp_threadinfo(this);
		tinfo->m_tid = element.event->tid();
		// For our (current) purposes, the tid and the pid always match.
		// This means that this is the main thread of a process.
		tinfo->m_pid = tinfo->m_tid;
		add_thread(tinfo);
	}

	if(!element.count)
	{
		// We pass the raw pointer of the event back to the client, so we can't
		// just pop the event and let it die. We have to save it off.
		m_completed_events.push_back(element);
		m_events.pop_front();
	}

	if(m_analyzer)
	{
		m_analyzer->process_event(*evt, sinsp_analyzer::DF_NONE);

		// Wait for async processing to complete
		m_analyzer->flush_drain();
	}

	return SCAP_SUCCESS;
}


void sinsp_mock::get_capture_stats(scap_stats *stats)
{
	*stats = m_scap_stats;
}

}
