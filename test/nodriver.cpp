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
		auto* thread_table = param.m_inspector->m_thread_manager->get_threads();
		EXPECT_GT(thread_table->size(), 0u);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run_nodriver(test, callback);});
}

TEST(nodriver, proc_fileio)
{
	//
	// TEST CODE
	//
	sinsp_procfs_parser procfs_parser(4, 500, true);
	sinsp_proc_file_stats io_stats;
	procfs_parser.read_proc_file_stats(getpid(), &io_stats);

	uint32_t bytes_written = 0;
	auto f = fopen("/dev/null", "w");
	ASSERT_TRUE(f);
	char buffer[1024];
	for(auto j = 0; j < 100; ++j)
	{
		bytes_written += fwrite(buffer, sizeof(char), 1024, f);
	}
	fflush(f);
	fclose(f);

	procfs_parser.read_proc_file_stats(getpid(), &io_stats);

	EXPECT_TRUE(io_stats.has_values());
	EXPECT_GE(io_stats.m_write_bytes, bytes_written);
}