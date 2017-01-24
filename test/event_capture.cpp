#define VISIBILITY_PRIVATE

#include "event_capture.h"
#include <sinsp.h>
#include <gtest.h>

#define ONE_SECOND_MS 1000

void event_capture::capture()
{
	m_inspector = new sinsp();
	m_analyzer = new sinsp_analyzer(m_inspector);
	m_inspector->m_analyzer = m_analyzer;
	
	m_analyzer->set_configuration(m_configuration);

	if(m_max_thread_table_size != 0)
	{
		m_inspector->m_max_thread_table_size = m_max_thread_table_size;
	}
	
	if(m_thread_timeout_ns != 0)
	{
		m_inspector->m_thread_timeout_ns = m_thread_timeout_ns;
	}
	
	if(m_inactive_thread_scan_time_ns != 0)
	{
		m_inspector->m_inactive_thread_scan_time_ns = m_inactive_thread_scan_time_ns;
	}

	m_inspector->set_get_procs_cpu_from_driver(true);

	if(m_analyzer_callback != NULL)
	{
		m_analyzer->set_sample_callback(m_analyzer_callback);
	}

	m_param.m_inspector = m_inspector;
	try
	{
		if(m_mode == SCAP_MODE_NODRIVER)
		{
			m_inspector->open_nodriver();
		}
		else
		{
			m_inspector->open(ONE_SECOND_MS);
		}
	}
	catch(...)
	{
		m_start_failed = true;
		m_start_failure_message = "couldn't open inspector (maybe driver hasn't been loaded yet?)";
		m_capture_started.set();
		delete m_inspector;
		delete m_analyzer;
		return;
	}

	const ::testing::TestInfo *const test_info =
	    ::testing::UnitTest::GetInstance()->current_test_info();

	m_inspector->set_debug_mode(true);
	m_inspector->set_hostname_and_port_resolution_mode(false);

	if(m_mode != SCAP_MODE_NODRIVER)
	{
		m_dump_filename = string("./captures/") + test_info->test_case_name() + "_" + test_info->name() + ".scap";
		try
		{
			m_inspector->autodump_start(m_dump_filename, false);
		}
		catch(...)
		{
			m_start_failed = true;
			m_start_failure_message = string("couldn't start dumping to ") + m_dump_filename;
			m_capture_started.set();
			delete m_inspector;
			delete m_analyzer;
			return;
		}
	}

	bool signaled_start = false;
	sinsp_evt *event;
	bool result = true;
	int32_t next_result = SCAP_SUCCESS;
	while(!m_stopped && result && !::testing::Test::HasFatalFailure())
	{
		if(SCAP_SUCCESS == (next_result = m_inspector->next(&event)))
		{
			result = handle_event(event);
		}
		if(!signaled_start)
		{
			signaled_start = true;
			m_capture_started.set();
		}
	}
	
	if(m_mode != SCAP_MODE_NODRIVER)
	{
		m_inspector->stop_capture();
		
		uint32_t n_timeouts = 0;
		while(result && !::testing::Test::HasFatalFailure())
		{
			next_result = m_inspector->next(&event);
			if(next_result == SCAP_TIMEOUT)
			{
				n_timeouts++;

				if(n_timeouts < 3)
				{
					continue;
				}
				else
				{
					break;
				}
			}

			if(next_result != SCAP_SUCCESS)
			{
				break;
			}
			result = handle_event(event);
		}
		while(SCAP_SUCCESS == m_inspector->next(&event))
		{
			// just consume the events
		}
	}
	
	delete m_inspector;
	delete m_analyzer;
	m_capture_stopped.set();
}
