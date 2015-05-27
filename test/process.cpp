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

#include "sinsp.h"
#include "sinsp_int.h"
#include "protodecoder.h"
#include "procfs_parser.h"
#include "analyzer_thread.h"


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

				sleep(1);
			 
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
				EXPECT_EQ("<s>", e->get_param_value_str("fd"));
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
				EXPECT_EQ("<i>", e->get_param_value_str("fd"));
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
	EXPECT_EQ(NULL, inspector.get_thread(0xffff, false, true));

	//
	// Even the second, to confirm that nothing was added to the table
	//
	EXPECT_EQ(NULL, inspector.get_thread(0xffff, false, true));

	//
	// Now a new entry should be added to the process list...
	//
	sinsp_threadinfo* tinfo = inspector.get_thread(0xffff, true, true);
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if(tinfo)
	{
		EXPECT_EQ("<NA>", tinfo->m_comm);
	}

	//
	// ...and confirm
	//
	tinfo = inspector.get_thread(0xffff, false, true);
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if(tinfo)
	{
		EXPECT_EQ("<NA>", tinfo->m_comm);
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

#if 0
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
		else if(type == PPME_SYSCALL_PRLIMIT_X)
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
	vector<double> loads;
	vector<double> idles;
	vector<double> steals;
	uint32_t j, k;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	int64_t memkb =  (int64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;

	sinsp_procfs_parser pparser(nprocs, memkb, true);

	pparser.get_cpus_load(&loads, &idles, &steals);
	sleep(1);
	EXPECT_EQ((int32_t)0, (int32_t)loads.size());

	for(j = 0; j < 5; j++)
	{
		pparser.get_cpus_load(&loads, &idles, &steals);
		EXPECT_EQ((int32_t)sysconf(_SC_NPROCESSORS_ONLN), (int32_t)loads.size());

		for(k = 0; k < loads.size(); k++)
		{
			EXPECT_LE((double)0, loads[k]);
			EXPECT_GT((double)105, loads[k]);
		}

		sleep(1);
	}
}

TEST_F(sys_call_test, procfs_cpuload_longinterval)
{
	vector<double> loads;
	vector<double> idles;
	vector<double> steals;
	uint32_t j, k;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	int64_t memkb =  (int64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;

	sinsp_procfs_parser pparser(nprocs, memkb, true);

	pparser.get_cpus_load(&loads, &idles, &steals);
	sleep(1);
	EXPECT_EQ((int32_t)0, (int32_t)loads.size());

	for(j = 0; j < 3; j++)
	{
		pparser.get_cpus_load(&loads, &idles, &steals);
		EXPECT_EQ((int32_t)sysconf(_SC_NPROCESSORS_ONLN), (int32_t)loads.size());

		for(k = 0; k < loads.size(); k++)
		{
			EXPECT_LE((double)0, loads[k]);
			EXPECT_GE((double)100, loads[k]);
		}

		sleep(3);
	}
}

TEST_F(sys_call_test, procfs_globalcpuload)
{
	double load;
	uint32_t j;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	int64_t memkb =  (int64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;

	sinsp_procfs_parser pparser(nprocs, memkb, true);

	load = pparser.get_global_cpu_load();
	sleep(1);
	EXPECT_EQ((int32_t)-1, (int32_t)load);

	for(j = 0; j < 5; j++)
	{
		load = pparser.get_global_cpu_load();
		EXPECT_NE((double)-1, (int32_t)load);
		EXPECT_LE((double)0, load);
		EXPECT_GE((double)100, load);
		sleep(1);
	}
}

TEST_F(sys_call_test, procfs_processcpuload)
{
	double load;
	uint32_t j, k;
	uint32_t t = 1;
	int pid = getpid();
	uint64_t old_global_total_jiffies;
	uint64_t cur_global_total_jiffies;
	uint64_t old_proc_jiffies = (uint64_t)-1LL;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	int64_t memkb =  (int64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;

	sinsp_procfs_parser pparser(nprocs, memkb, true);

	load = pparser.get_global_cpu_load(&old_global_total_jiffies);
	EXPECT_EQ((double)-1, load);
	load = pparser.get_process_cpu_load(pid, &old_proc_jiffies, 0);
	EXPECT_EQ((double)-1, load);
	
	sleep(1);

	for(j = 20; j > 10; j--)
	{
		for(k = 0; k < 5000000 * j; k++)
		{
			t += k;
			t = t % 35689;
		}

		pparser.get_global_cpu_load(&cur_global_total_jiffies);
		load = pparser.get_process_cpu_load(pid, &old_proc_jiffies, cur_global_total_jiffies - old_global_total_jiffies);
		EXPECT_NE((double)-1, load);
		EXPECT_LE((double)0, load);
		EXPECT_GE((double)100, load);
		old_global_total_jiffies = cur_global_total_jiffies;

		usleep(100000);
	}
}

class loadthread
{
public:
	loadthread()
	{
		m_die = false;
		m_tid = -1;
	}

	void run()
	{
		uint64_t k = 0;
		uint64_t t = 0;
		m_tid = syscall(SYS_gettid);

		while(true)
		{
			t += k;
			t = t % 35689;

			if(m_die)
			{
				return;
			}
		}
	}

	int64_t get_tid()
	{
		return m_tid;
	}

	volatile bool m_die;
	int64_t m_tid;
};

TEST_F(sys_call_test, procfs_processchild_cpuload)
{
	double load;
	uint32_t j;
	int pid = getpid();
	uint64_t old_global_total_jiffies;
	uint64_t cur_global_total_jiffies;
	uint64_t old_global_steal_jiffies;
	uint64_t cur_global_steal_jiffies;
	uint64_t old_proc_jiffies = (uint64_t)-1LL;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	int64_t memkb =  (int64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;
	uint32_t num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	uint32_t m = (num_cpus > 2) ? 2:num_cpus;
 
	Poco::Thread th;
	loadthread ct;
	Poco::RunnableAdapter<loadthread> runnable(ct, &loadthread::run);
	th.start(runnable);

	Poco::Thread th1;
	loadthread ct1;
	Poco::RunnableAdapter<loadthread> runnable1(ct1, &loadthread::run);
	th1.start(runnable1);

	sinsp_procfs_parser pparser(nprocs, memkb, true);

	pparser.get_global_cpu_load(&old_global_total_jiffies, NULL, &old_global_steal_jiffies);
	load = pparser.get_process_cpu_load(pid, &old_proc_jiffies, 0);

	sleep(1);

	EXPECT_EQ((double)-1, load);

	for(j = 0; j < 3; j++)
	{
		pparser.get_global_cpu_load(&cur_global_total_jiffies, NULL, &cur_global_steal_jiffies);
		load = pparser.get_process_cpu_load(pid, &old_proc_jiffies, cur_global_total_jiffies - old_global_total_jiffies);

		sleep(1);

		double stolen = (double) (cur_global_steal_jiffies - old_global_steal_jiffies) * 100 / (cur_global_total_jiffies - old_global_total_jiffies);

		//
		// When there's steal time, on AWS there are processes that if ran at 100% will have low spikes of 10-20% cpu for a second 
		// (verified, top/htop show the exact same information, even after accounting steal time). 
		// On Digital Ocean instead, every process always consumes 100% after accounting steal time.
		// It recently broke because the stolen time was not accounted as a global cpu time, so the math was working most of the time, but
		// now that the measurements are more precise, the issue is more frequent, so in case of stolen time, we'll just lower the threshold.
		//
		EXPECT_LE((double)m * 100 - 15 - stolen, load);
		EXPECT_GE((double)m * 100 + 15, load);

		old_global_total_jiffies = cur_global_total_jiffies;
		old_global_steal_jiffies = cur_global_steal_jiffies;
	}

	ct.m_die = true;
	ct1.m_die = true;

	th.join();
	th1.join();
}

TEST_F(sys_call_test, procfs_globalmemory)
{
	int64_t memusage;
	int64_t swapusage;
	uint32_t j;
	int32_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	int64_t memkb =  (int64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / 1024;

	sinsp_procfs_parser pparser(nprocs, memkb, true);

	for(j = 0; j < 5; j++)
	{
		pparser.get_global_mem_usage_kb(&memusage, &swapusage);
		EXPECT_NE((int64_t)-1, memusage);
		EXPECT_LE((int64_t)0, memusage);
		EXPECT_GE((int64_t)memkb, memusage);	
		EXPECT_NE((int64_t)-1, swapusage);
		EXPECT_LE((int64_t)0, swapusage);
		sleep(1);
	}
}

TEST_F(sys_call_test, process_scap_proc_get)
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
		usleep(1000);

		int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		EXPECT_LT(0, s);

		int s1 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		EXPECT_LT(0, s);

		usleep(1000000);

		close(s);
		close(s1);
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
				scap_threadinfo* scap_proc;

				scap_proc = scap_proc_get(param.m_inspector->m_h, 0, false);
				EXPECT_EQ(NULL, (void*)scap_proc);
				
				int64_t tid = e->get_tid();
				scap_proc = scap_proc_get(param.m_inspector->m_h, tid, false);
				EXPECT_NE((void*)NULL, (void*)scap_proc);
			}
			else
			{
				scap_threadinfo* scap_proc;
				scap_fdinfo *fdi;
				scap_fdinfo *tfdi;
				uint32_t nsocks = 0;
				int64_t tid = e->get_tid();

				//
				// try with scan_sockets=true
				//
				scap_proc = scap_proc_get(param.m_inspector->m_h, tid, false);
				EXPECT_NE((void*)NULL, (void*)scap_proc);

				HASH_ITER(hh, scap_proc->fdlist, fdi, tfdi)
				{
					if(fdi->type == SCAP_FD_IPV4_SOCK)
					{
						nsocks++;
					}
				}

				EXPECT_EQ(0, nsocks);

				//
				// try with scan_sockets=false
				//
				scap_proc = scap_proc_get(param.m_inspector->m_h, tid, true);
				EXPECT_NE((void*)NULL, (void*)scap_proc);

				HASH_ITER(hh, scap_proc->fdlist, fdi, tfdi)
				{
					if(fdi->type == SCAP_FD_IPV4_SOCK)
					{
						nsocks++;
					}
				}

				EXPECT_EQ(0, nsocks);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
}

TEST_F(sys_call_test, procinfo_processchild_cpuload)
{
	int callnum = 0;
	int lastcpu = 0;
	int64_t ctid = -1;

	Poco::Thread th;
	loadthread ct;
	Poco::RunnableAdapter<loadthread> runnable(ct, &loadthread::run);
	th.start(runnable);

	sleep(2);
	ctid = ct.get_tid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return true;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		for(uint32_t j = 0; j < 5; j++)
		{
			sleep(1);
		}

		ct.m_die = true;

		th.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_PROCINFO_E)
		{
			sinsp_threadinfo* tinfo = e->get_thread_info();

			if(tinfo)
			{
				if(tinfo->m_tid == ctid)
				{
					uint64_t tcpu;

					sinsp_evt_param* parinfo = e->get_param(0);
					tcpu = *(uint64_t*)parinfo->m_val;

					uint64_t delta = tcpu - lastcpu;

					printf("%d:%d)%d:%d)%d >> %d\n", (int)callnum, (int)ctid, (int)tinfo->m_pid, (int)tinfo->m_tid, (int)tcpu, (int)delta);

					if(callnum != 0)
					{
						EXPECT_GT(delta, 90);
						EXPECT_LT(delta, 110);
					}

					lastcpu = tcpu;

					callnum++;
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(5, callnum);
}

TEST_F(sys_call_test, procinfo_two_processchilds_cpuload)
{
	int callnum = 0;
	int lastcpu = 0;
	int lastcpu1 = 0;

	Poco::Thread th;
	loadthread ct;
	Poco::RunnableAdapter<loadthread> runnable(ct, &loadthread::run);
	th.start(runnable);

	Poco::Thread th1;
	loadthread ct1;
	Poco::RunnableAdapter<loadthread> runnable1(ct1, &loadthread::run);
	th1.start(runnable1);

	sleep(2);
	int64_t ctid = ct.get_tid();
	int64_t ctid1 = ct1.get_tid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return true;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		for(uint32_t j = 0; j < 5; j++)
		{
			sleep(1);
		}

		ct.m_die = true;
		ct1.m_die = true;

		th.join();
		th1.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_PROCINFO_E)
		{
			sinsp_threadinfo* tinfo = e->get_thread_info();

			if(tinfo)
			{
				if(tinfo->m_tid == ctid)
				{
					uint64_t tcpu;

					sinsp_evt_param* parinfo = e->get_param(0);
					tcpu = *(uint64_t*)parinfo->m_val;

					uint64_t delta = tcpu - lastcpu;

					printf("%d:%d)%d:%d)%d >> %d\n", (int)callnum, (int)ctid, (int)tinfo->m_pid, (int)tinfo->m_tid, (int)tcpu, (int)delta);

					if(callnum > 2)
					{
						EXPECT_GT(delta, 0);
						EXPECT_LT(delta, 110);
					}

					lastcpu = tcpu;

					callnum++;
				}
				else if(tinfo->m_tid == ctid1)
				{
					uint64_t tcpu;

					sinsp_evt_param* parinfo = e->get_param(0);
					tcpu = *(uint64_t*)parinfo->m_val;

					uint64_t delta = tcpu - lastcpu1;
 
					printf("%d:%d)%d:%d)%d >> %d\n", (int)callnum, (int)ctid, (int)tinfo->m_pid, (int)tinfo->m_tid, (int)tcpu, (int)delta);

					if(callnum > 2)
					{
						EXPECT_GT(delta, 0);
						EXPECT_LT(delta, 110);
					}

					lastcpu1 = tcpu;

					callnum++;
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
}

/*
class childthread
{
public:
	void run()
	{
		m_tid = syscall(SYS_gettid);
		tee(-1, -1, 0, 0);
		sleep(1);
	}

	int64_t get_tid()
	{
		return m_tid;
	}

private:
	int64_t m_tid;
};

TEST_F(sys_call_test, program_child_with_threads)
{
	int ctid;
	int cctid;
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return true;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		ctid = fork();

		if(ctid == 0)
		{
			//
			// CHILD PROCESS
			//
			cctid = fork();
	
			if(cctid == 0)
			{
				//
				// GRANDCHILD PROCESS
				//
				Poco::Thread th;
				childthread ct;
				Poco::RunnableAdapter<childthread> runnable(ct, &childthread::run);
				th.start(runnable);
				th.join();
				tee(-1, -1, 0, 0);
				_exit(0);
			}
			else
			{
				int status;
				wait(&status);	// wait for child to exit, and store its status
								// Use WEXITSTATUS to validate status.
								// some time so the samples can flush
				sleep(2);
				tee(-1, -1, 0, 0);
				_exit(0);
			}
		}
		else
		{
			int status;
			wait(&status);	// wait for child to exit, and store its status
							// Use WEXITSTATUS to validate status.
							// some time so the samples can flush
			sleep(2);
//			tee(-1, -1, 0, 0);
			sleep(1);
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;
		uint16_t type = evt->get_type();

		if(type == PPME_GENERIC_E)
		{
			if(NumberParser::parse(evt->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				if(callnum == 0)
				{
					sinsp_threadinfo* tinfo;

					tinfo = param.m_inspector->m_thread_manager->get_thread(evt->get_tid(), true);
					EXPECT_EQ((uint64_t)0, tinfo->m_nchilds);
					tinfo = param.m_inspector->m_thread_manager->get_thread(tinfo->m_ptid, true);
					EXPECT_EQ((uint64_t)1, tinfo->m_nchilds);
					tinfo = param.m_inspector->m_thread_manager->get_thread(tinfo->m_ptid, true);
					EXPECT_EQ((uint64_t)1, tinfo->m_nchilds);
					tinfo = param.m_inspector->m_thread_manager->get_thread(tinfo->m_ptid, true);
					EXPECT_EQ((uint64_t)3, tinfo->m_nchilds);
				}
				else if(callnum == 1)
				{
					sinsp_threadinfo* tinfo;

					tinfo = param.m_inspector->m_thread_manager->get_thread(evt->get_tid(), true);
					EXPECT_EQ((uint64_t)1, tinfo->m_nchilds);
					tinfo = param.m_inspector->m_thread_manager->get_thread(tinfo->m_ptid, true);
					EXPECT_EQ((uint64_t)1, tinfo->m_nchilds);
					tinfo = param.m_inspector->m_thread_manager->get_thread(tinfo->m_ptid, true);
					EXPECT_EQ((uint64_t)3, tinfo->m_nchilds);
				}
				else if(callnum == 2)
				{
					sinsp_threadinfo* tinfo;

					tinfo = param.m_inspector->m_thread_manager->get_thread(evt->get_tid(), true);
					EXPECT_EQ((uint64_t)0, tinfo->m_nchilds);
					tinfo = param.m_inspector->m_thread_manager->get_thread(tinfo->m_ptid, true);
					EXPECT_EQ((uint64_t)2, tinfo->m_nchilds);
				}

				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

//	EXPECT_EQ(2, callnum);
	sleep(2);
}
*/
/*
TEST_F(sys_call_test, nested_program_childs)
{
	int ctid;
	int cctid, cctid1, cctid2;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return true;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		ctid = fork();

		if(ctid == 0)
		{
			//
			// CHILD PROCESS
			//
			cctid = fork();
	
			if(cctid == 0)
			{
				//
				// CHILD PROCESS
				//
				cctid1 = fork();
		
				if(cctid1 == 0)
				{
					//
					// CHILD PROCESS
					//
					cctid2 = fork();
					
					if(cctid2 == 0)
					{
						_exit(0);
					}
					else
					{
						int status;
						wait(&status);
						_exit(0);
					}
				}
				else
				{
					int status;
					wait(&status);
					_exit(0);
				}
			}
			else
			{
				int status;
				wait(&status);
				_exit(0);
			}
		}
		else
		{
			int status;
			wait(&status);
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;
		uint16_t type = evt->get_type();

		if(type == PPME_CLONE_16_X)
		{
			sinsp_threadinfo* tinfo = evt->get_thread_info(false);
			EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);

			sinsp_threadinfo* ptinfo = tinfo->m_ainfo->get_main_program_thread();
			EXPECT_EQ(getpid(), ptinfo->m_tid);
		}		
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
}
*/