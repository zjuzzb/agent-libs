//
// Created by Luca Marturana on 18/01/2017.
//

#define VISIBILITY_PRIVATE

#include <sys/syscall.h>
#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <list>
#include <cassert>
#include "scap-int.h"

TEST(nodriver, smoke)
{
	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		// Wait a bit so the first flush will be executed
		usleep(500);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		auto* thread_table = param.m_inspector->m_thread_manager->get_threads();
		EXPECT_GT(thread_table->size(), 0);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run_nodriver(test, callback);});
}