#include "event_capture.h"
#include <sinsp.h>
#include <gtest.h>

#define ONE_SECOND_MS 1000

void event_capture::capture()
{
	m_inspector = new sinsp;
	
	m_inspector->set_configuration(m_configuration);
	
	m_param.m_inspector = m_inspector;
	try
	{
		m_inspector->open(ONE_SECOND_MS);
	}
	catch(...)
	{
		m_start_failed = true;
		m_start_failure_message = "couldn't open inspector (maybe driver hasn't been loaded yet?)";
		m_capture_started.set();
		delete m_inspector;
		return;
	}

	const ::testing::TestInfo *const test_info =
	    ::testing::UnitTest::GetInstance()->current_test_info();
	m_dump_filename = string("./captures/") + test_info->test_case_name() + "_" + test_info->name() + ".scap";
	try
	{
		m_inspector->start_dump(m_dump_filename);
	}
	catch(...)
	{
		m_start_failed = true;
		m_start_failure_message = string("couldn't start dumping to ") + m_dump_filename;
		m_capture_started.set();
		delete m_inspector;
		return;
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
	
	m_inspector->stop_capture();
	while(result && SCAP_SUCCESS == (next_result = m_inspector->next(&event)) && !::testing::Test::HasFatalFailure())
	{
		result = handle_event(event);
	}
	while(SCAP_SUCCESS == m_inspector->next(&event))
	{
		// just consume the events
	}
	delete m_inspector;
	m_capture_stopped.set();
}