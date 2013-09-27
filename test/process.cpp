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
#include <procfs_parser.h>

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

TEST_F(sys_call_test, process_rlimit)
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
		struct rlimit rl;

		getrlimit(RLIMIT_NOFILE, (struct rlimit*)33);
		getrlimit(RLIMIT_NOFILE, &rl);
		rl.rlim_cur = 500;
		rl.rlim_max = 1000;
		setrlimit(RLIMIT_NOFILE, &rl);
		getrlimit(RLIMIT_NOFILE, &rl);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_GETRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE, NumberParser::parse64(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if(type == PPME_SYSCALL_GETRLIMIT_X)
		{
			if(callnum == 1)
			{
				EXPECT_GT((int64_t)0, NumberParser::parse64(e->get_param_value_str("res", false)));
			}
			else
			{
				EXPECT_EQ((int64_t)0, NumberParser::parse64(e->get_param_value_str("res", false)));

				if(callnum == 7)
				{
					EXPECT_EQ((int64_t)500, NumberParser::parse64(e->get_param_value_str("cur", false)));
					EXPECT_EQ((int64_t)1000, NumberParser::parse64(e->get_param_value_str("max", false)));
				}
			}

			callnum++;
		}
		if(type == PPME_SYSCALL_SETRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE, NumberParser::parse64(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if(type == PPME_SYSCALL_SETRLIMIT_X)
		{
			EXPECT_EQ((int64_t)0, NumberParser::parse64(e->get_param_value_str("res", false)));

			if(callnum == 5)
			{
				EXPECT_EQ((int64_t)500, NumberParser::parse64(e->get_param_value_str("cur", false)));
				EXPECT_EQ((int64_t)1000, NumberParser::parse64(e->get_param_value_str("max", false)));
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(8, callnum);
}

#ifdef SYS_prlimit64
TEST_F(sys_call_test, process_prlimit)
{
	int callnum = 0;
	struct rlimit tmprl;
	struct rlimit orirl;

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
		struct rlimit newrl;
		struct rlimit oldrl;

		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &orirl);
		newrl.rlim_cur = 500;
		newrl.rlim_max = 1000;
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, &newrl, &oldrl);
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &oldrl);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PRLIMIT_E)
		{
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE, NumberParser::parse64(e->get_param_value_str("resource", false)));
			EXPECT_EQ((int64_t)getpid(), NumberParser::parse64(e->get_param_value_str("pid", false)));
			callnum++;
		}
		if(type == PPME_SYSCALL_PRLIMIT_X)
		{
			EXPECT_GE((int64_t)0, NumberParser::parse64(e->get_param_value_str("res", false)));

			if(callnum == 1)
			{
				EXPECT_EQ((int64_t)-1, NumberParser::parse64(e->get_param_value_str("newcur", false)));
				//EXPECT_EQ((int64_t)0, NumberParser::parse64(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)orirl.rlim_cur, NumberParser::parse64(e->get_param_value_str("oldcur", false)));
				//EXPECT_EQ((int64_t)orirl.rlim_max, NumberParser::parse64(e->get_param_value_str("oldmax", false)));
			}
			else if(callnum == 3)
			{
				EXPECT_EQ((int64_t)500, NumberParser::parse64(e->get_param_value_str("newcur", false)));
				//EXPECT_EQ((int64_t)1000, NumberParser::parse64(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)orirl.rlim_cur, NumberParser::parse64(e->get_param_value_str("oldcur", false)));
				//EXPECT_EQ((int64_t)orirl.rlim_max, NumberParser::parse64(e->get_param_value_str("oldmax", false)));
			}
			else if(callnum == 5)
			{
				EXPECT_EQ((int64_t)-1, NumberParser::parse64(e->get_param_value_str("newcur", false)));
				//EXPECT_EQ((int64_t)0, NumberParser::parse64(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)500, NumberParser::parse64(e->get_param_value_str("oldcur", false)));
				//EXPECT_EQ((int64_t)1000, NumberParser::parse64(e->get_param_value_str("oldmax", false)));
			}

			callnum++;
		}
	};

	if(syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &tmprl) != 0)
	{
		return;
	} 

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(6, callnum);
}
#endif

TEST_F(sys_call_test, procfs_cpuload)
{
	OUT vector<uint32_t> loads;
	uint32_t j, k;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	sinsp_procfs_parser pparser(nprocs);

	pparser.get_cpus_load(&loads);
	sleep(1);
	EXPECT_EQ((int32_t)0, (int32_t)loads.size());

	for(j = 0; j < 5; j++)
	{
		pparser.get_cpus_load(&loads);
		EXPECT_EQ((int32_t)sysconf(_SC_NPROCESSORS_ONLN), (int32_t)loads.size());

		for(k = 0; k < loads.size(); k++)
		{
			EXPECT_LE((uint32_t)0, loads[k]);
			EXPECT_GT((uint32_t)100, loads[k]);
		}

		sleep(1);
	}
}

TEST_F(sys_call_test, procfs_cpuload_longinterval)
{
	OUT vector<uint32_t> loads;
	uint32_t j, k;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	sinsp_procfs_parser pparser(nprocs);

	pparser.get_cpus_load(&loads);
	sleep(1);
	EXPECT_EQ((int32_t)0, (int32_t)loads.size());

	for(j = 0; j < 3; j++)
	{
		pparser.get_cpus_load(&loads);
		EXPECT_EQ((int32_t)sysconf(_SC_NPROCESSORS_ONLN), (int32_t)loads.size());

		for(k = 0; k < loads.size(); k++)
		{
			EXPECT_LE((uint32_t)0, loads[k]);
			EXPECT_GE((uint32_t)100, loads[k]);
		}

		sleep(3);
	}
}

TEST_F(sys_call_test, procfs_globalcpuload)
{
	uint32_t load;
	uint32_t j;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	sinsp_procfs_parser pparser(nprocs);

	load = pparser.get_global_cpu_load();
	sleep(1);
	EXPECT_EQ((int32_t)-1, (int32_t)load);

	for(j = 0; j < 5; j++)
	{
		load = pparser.get_global_cpu_load();
		EXPECT_NE((int32_t)-1, (int32_t)load);
		EXPECT_LE((uint32_t)0, load);
		EXPECT_GE((uint32_t)100, load);
		sleep(1);
	}
}

TEST_F(sys_call_test, procfs_processcpuload)
{
	uint32_t load;
	uint32_t j, k;
	uint32_t t = 1;
	int pid = getpid();
	uint64_t old_global_total_jiffies;
	uint64_t cur_global_total_jiffies;
	uint64_t old_proc_jiffies = (uint64_t)-1LL;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	sinsp_procfs_parser pparser(nprocs);

	pparser.get_global_cpu_load(&old_global_total_jiffies);
	load = pparser.get_process_cpu_load(pid, &old_proc_jiffies, 0);
	
	sleep(1);

	EXPECT_EQ((int32_t)-1, (int32_t)load);

	for(j = 20; j > 10; j--)
	{
		for(k = 0; k < 5000000 * j; k++)
		{
			t += k;
			t = t % 35689;
		}

		pparser.get_global_cpu_load(&cur_global_total_jiffies);
		load = pparser.get_process_cpu_load(pid, &old_proc_jiffies, cur_global_total_jiffies - old_global_total_jiffies);

		EXPECT_NE((int32_t)-1, (int32_t)load);
		EXPECT_LE((uint32_t)0, load);
		EXPECT_GE((uint32_t)100, load);
		old_global_total_jiffies = cur_global_total_jiffies;
	}
}
