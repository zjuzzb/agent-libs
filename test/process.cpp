#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>

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

using namespace std;

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;

TEST_F(sys_call_test, process_signalfd_kill)
{
	int callnum = 0;

	int ptid;	// parent tid
	int ctid;	// child tid
	int gptid;	// grandparent tid
	int xstatus = 33;	// child exit value
	int ssfd;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == ptid || evt->get_tid() == ctid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int status;
		int sfd;
		ctid = fork();

		if(ctid >= 0) // fork succeeded
		{
			if(ctid == 0)
			{
				//
				// CHILD PROCESS
				//
				sigset_t mask;
			 
				/* We will handle SIGTERM and SIGINT. */
				sigemptyset (&mask);
				sigaddset (&mask, SIGTERM);
				sigaddset (&mask, SIGINT);
			 
				/* Block the signals thet we handle using signalfd(), so they don't
				 * cause signal handlers or default signal actions to execute. */
				if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) 
				{
					FAIL();
				}
			 
				/* Create a file descriptor from which we will read the signals. */
				sfd = signalfd (-1, &mask, 0);
				if (sfd < 0) 
				{
					FAIL();
				}

				while (true) 
				{
			 
					/** The buffor for read(), this structure contains information
					 * about the signal we've read. */
					struct signalfd_siginfo si;
			 
					ssize_t res;
			 
					res = read (sfd, &si, sizeof(si));
			 
					if (res < 0) 
					{
						FAIL();
					}
					if (res != sizeof(si)) 
					{
						FAIL();
					}
			 
					if (si.ssi_signo == SIGTERM)
					{
						continue;
					}
					else if (si.ssi_signo == SIGINT) 
					{			 
						break;
					}
					else 
					{
						FAIL();
					}
				}

				/* Close the file descriptor if we no longer need it. */
				close (sfd);
			 
				//
				// Remember to use _exit or the test system will get fucked!!
				//
				_exit(xstatus);
			}
			else
			{
				//
				// PARENT PROCESS
				//
				ptid = getpid();
				gptid = getppid();

				//
				// Give the client some time install its handlers
				//
				usleep(200000);

				kill(ctid, SIGTERM);
				kill(ctid, SIGINT);

				//
				// Wait for child to exit, and store its status
				//
				wait(&status);	
			}
		}
		else
		{
			FAIL();
		}

	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SIGNALFD_E)
		{
			EXPECT_EQ(-1, NumberParser::parse(e->get_param_value_str("fd", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("mask")));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("flags")));
			callnum++;
		}
		else if(type == PPME_SYSCALL_SIGNALFD_X)
		{
			ssfd = NumberParser::parse(e->get_param_value_str("res", false));
			EXPECT_EQ(ssfd, NumberParser::parse(e->get_param_value_str("res", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_READ_E)
		{
			if(callnum == 2)
			{
				EXPECT_EQ("s", e->get_param_value_str("fd"));
				EXPECT_EQ(ssfd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_KILL_E)
		{
			if(callnum == 3)
			{
				EXPECT_EQ("test", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, NumberParser::parse(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGTERM", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGTERM, NumberParser::parse(e->get_param_value_str("sig", false)));
				callnum++;
			}
			else if(callnum == 5)
			{
				EXPECT_EQ("test", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, NumberParser::parse(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGINT", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGINT, NumberParser::parse(e->get_param_value_str("sig", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_KILL_X)
		{
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(7, callnum);
}

TEST_F(sys_call_test, process_usleep)
{
	int callnum = 0;

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
		usleep(123456);
		sleep(5);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_NANOSLEEP_E)
		{
			if(callnum == 0)
			{
				if(NumberParser::parse(e->get_param_value_str("interval", false)) == 123456000)
				{
					callnum++;
				}
			}
			else if(callnum == 2)
			{
				EXPECT_EQ(5000000000, NumberParser::parse64(e->get_param_value_str("interval", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_NANOSLEEP_X)
		{
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, callnum);
}

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

TEST_F(sys_call_test, process_inotify)
{
	int callnum = 0;
	int fd;

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
		int length;
		int wd;
		char buffer[EVENT_BUF_LEN];

		//
		// creating the INOTIFY instance
		//
		fd = inotify_init();

		/*checking for error*/
		if ( fd < 0 ) 
		{
			FAIL();
		}

		//
		// The IN_MODIFY flag causes a notification when a file is written, which should
		// heppen immediately in captures
		//
		wd = inotify_add_watch( fd, "./captures", IN_MODIFY );

		//
		// read to determine the event changes
		//
		length = read( fd, buffer, EVENT_BUF_LEN ); 
		if ( length < 0 ) 
		{
			FAIL();
		}  

		//
		// removing the watch
		//
		inotify_rm_watch( fd, wd );

		//
		// closing the INOTIFY instance
		//
		close( fd );
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_INOTIFY_INIT_E)
		{
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("flags")));
			callnum++;
		}
		else if(type == PPME_SYSCALL_INOTIFY_INIT_X)
		{
			EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("res", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_READ_E)
		{
			if(callnum == 2)
			{
				EXPECT_EQ("i", e->get_param_value_str("fd"));
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(3, callnum);
}

TEST(procinfo, process_not_existent)
{
	sinsp inspector;
	
	inspector.open(1000);

	//
	// The first lookup should fail
	//
	EXPECT_EQ(NULL, inspector.get_thread(0xffff, false));

	//
	// Even the second, to confirm that nothing was added to the table
	//
	EXPECT_EQ(NULL, inspector.get_thread(0xffff, false));

	//
	// Now a new entry should be added to the process list...
	//
	sinsp_threadinfo* tinfo = inspector.get_thread(0xffff, true);
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if(tinfo)
	{
		EXPECT_EQ("Unknown", tinfo->m_comm);
	}

	//
	// ...and confirm
	//
	tinfo = inspector.get_thread(0xffff, false);
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if(tinfo)
	{
		EXPECT_EQ("Unknown", tinfo->m_comm);
	}

	inspector.close();
}

//
// This test is compiled in release mode only because in debug mode it would 
// cause a million of assertions to fire
//
//#ifndef _DEBUG
#if 0
TEST_F(sys_call_test, process_thread_table_limit)
{
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
		sleep(1);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);

		return;
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{		
		sinsp_evt *evt = param.m_evt;

printf("@@@@@@@@@3\n");		
		if(evt->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				ASSERT_EQ(3, (int)param.m_inspector->m_configuration.get_max_thread_table_size());

				ASSERT_EQ(3, (int)param.m_inspector->m_thread_manager->get_thread_count());
			}
		}
	};

	sinsp_configuration configuration;
	//
	// Set a very low thread table size
	//
	configuration.set_max_thread_table_size(3);

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration);});
}
#endif // _DEBUG