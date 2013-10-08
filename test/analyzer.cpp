#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define VISIBILITY_PRIVATE

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <list>
#include <cassert>
#include <event.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/inotify.h>

#include <sinsp.h>
#include <sinsp_int.h>
#include <sinsp_errno.h>
#include "sinsp.h"
#include "sinsp_int.h"
#include "parsers.h"
#include "connectinfo.h"
#include "metrics.h"
#include <analyzer.h>

using namespace std;

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;

TEST_F(sys_call_test, analyzer_errors)
{
//	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		char* const* pnt1 = NULL;
		char* pnt2 = NULL;

		FILE* f = fopen("/nonexistent", "r");	// generates ENOENT
		f = fopen("/nonexistent", "r");
		f = fopen("/nonexistent", "r");
		f = fopen("/nonexistent", "r");
		f = fopen("/nonexistent", "r");
		EXPECT_EQ(NULL, f);	// just to avoid the compiler from emitting a warning
		close(3333); // generates EBADF
		close(3333);
		close(3333);
		execve(pnt2, pnt1, pnt1); // generates EFAULT
		execve(pnt2, pnt1, pnt1);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if(e->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(e->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				sinsp_error_counters* ec = &param.m_inspector->m_analyzer->m_host_metrics.m_syscall_errors;

				EXPECT_NE((size_t)0, ec->m_table.size());

				EXPECT_LE((uint32_t)5, ec->m_table[SE_ENOENT].m_count);
				EXPECT_LE((uint32_t)3, ec->m_table[SE_EBADF].m_count);
				EXPECT_LE((uint32_t)2, ec->m_table[SE_EFAULT].m_count);

				sinsp_threadinfo* tinfo = param.m_inspector->m_thread_manager->get_thread(getpid());
				ec = &tinfo->m_procinfo->m_syscall_errors;

				EXPECT_NE((size_t)0, ec->m_table.size());

				EXPECT_LE((uint32_t)5, ec->m_table[SE_ENOENT].m_count);
				EXPECT_LE((uint32_t)3, ec->m_table[SE_EBADF].m_count);
				EXPECT_LE((uint32_t)2, ec->m_table[SE_EFAULT].m_count);

				map<int32_t, sinsp_counter_cnt>::iterator it;
				uint32_t j = 0;
				for(it = ec->m_table.begin(); it != ec->m_table.end(); ++it, j++)
				{
					if(j == 0)
					{
						EXPECT_EQ((int32_t)SE_ENOENT, it->first);
					}
					else if(j == 1)
					{
						EXPECT_EQ((int32_t)SE_EBADF, it->first);
					}
					else if(j == 2)
					{
						EXPECT_EQ((int32_t)SE_EFAULT, it->first);
					}
					else
					{
						break;
					}
				}

				EXPECT_LE((uint32_t)3, j);
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

//	EXPECT_EQ(7, callnum);
}
