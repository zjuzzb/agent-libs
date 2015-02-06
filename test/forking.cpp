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

using namespace std;
using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;

#define FILENAME "test_tmpfile"

TEST_F(sys_call_test, forking)
{
//	int callnum = 0;

	int ptid;	// parent tid
	int ctid;	// child tid
	int gptid;	// grandparent tid
	int xstatus = 33;	// child exit value

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
		pid_t childtid;
		int status;
		childtid = fork();

		int fd = creat(FILENAME, S_IRWXU);

		if(childtid >= 0) // fork succeeded
		{
			if(childtid == 0) // fork() returns 0 to the child process
			{
				ctid = getpid();
				usleep(100); // sleep for 0.1 seconds
				close(fd);
				_exit(xstatus); // child exits with specific return code
			}
			else // fork() returns new pid to the parent process
			{
				ptid = getpid();
				gptid = getppid();

				close(fd);

				wait(&status);	// wait for child to exit, and store its status
								// Use WEXITSTATUS to validate status.
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
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
}

TEST_F(sys_call_test, forking_while_scap_stopped)
{
	int ptid;	// parent tid
	int ctid;	// child tid
	int xstatus = 33;	// child exit value

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

		//
		// Stop the capture just before the fork so we lose the event.
		// WARNING: these calls are not thread safe, ping me if you
		// see a problem
		//
		inspector->stop_capture();

		ctid = fork();

		int fd = creat(FILENAME, S_IRWXU);

		if(ctid >= 0) // fork succeeded
		{
			if(ctid == 0) // fork() returns 0 to the child process
			{
				//
				// Restart the capture.
				// This is a bit messy because we are in the child
				// but it works because the underlying scap's fds
				// are duplicated so the ioctl will make its way to
				// the parent process as well.
				// It's a simple way to make sure the capture is started
				// after the child's clone returned.
				//
				inspector->start_capture();

				//
				// Wait for 5 seconds to make sure the process will still
				// exist when the sinsp will do the lookup to /proc
				//
				usleep(5000000);
				close(fd);
				_exit(xstatus); // child exits with specific return code
			}
			else // fork() returns new pid to the parent process
			{
				ptid = getpid();

				close(fd);

				wait(&status);	// wait for child to exit, and store its status
								// Use WEXITSTATUS to validate status.
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
	bool child_exists = false;
	bool parent_exists = false;

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if(e->get_type() == PPME_SCHEDSWITCH_1_E ||
			e->get_type() == PPME_SCHEDSWITCH_6_E)
		{
			return;
		}

		//
		// In both cases, the process should exist
		//
		if(e->get_tid() == ptid && !parent_exists)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);
			if(ti)
			{
				parent_exists = true;
			}

			EXPECT_NE((sinsp_threadinfo*)NULL, ti);
		}

		if(e->get_tid() == ctid && !child_exists)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);
			if(ti)
			{
				child_exists = true;
			}

			EXPECT_NE((sinsp_threadinfo*)NULL, ti);
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_TRUE(child_exists);
	EXPECT_TRUE(parent_exists);
}

TEST_F(sys_call_test, forking_process_expired)
{
	int ptid;	// parent tid
	int ctid;	// child tid
	int status;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == ptid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		ctid = fork();

		if(ctid >= 0) // fork succeeded
		{
			if(ctid == 0) // fork() returns 0 to the child process
			{
				pause();
				FAIL();
			}
			else // fork() returns new pid to the parent process
			{
				ptid = getpid();

				//
				// Wait 10 seconds. During this time, the process should NOT be removed
				//
				sleep(10);

				kill(ctid, SIGUSR1);
				wait(&status);
			}
		}
		else
		{
			FAIL();
		}
	};

	bool sleep_caught = false;

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if(e->get_tid() == ptid)
		{
			if(e->get_type() == PPME_SYSCALL_NANOSLEEP_E && !sleep_caught)
			{
				//
				// The child should exist
				//
				sinsp_threadinfo* ti = param.m_inspector->get_thread(ctid, false, true);
				EXPECT_NE((sinsp_threadinfo*)NULL, ti);
			}
			else if(e->get_type() == PPME_SYSCALL_NANOSLEEP_X && !sleep_caught)
			{
				//
				// The child should exist
				//
				sinsp_threadinfo* ti = param.m_inspector->get_thread(ctid, false, true);
				EXPECT_NE((sinsp_threadinfo*)NULL, ti);
				//sinsp_threadinfo* ti = param.m_inspector->get_thread(ctid, false, true);
				//EXPECT_EQ(NULL, ti);
				sleep_caught = true;
			}
		}
		else
		{
			FAIL();
		}
	};

	sinsp_configuration configuration;

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, 
		callback, 
		filter, 
		configuration,
		NULL,
		0,
		5 * ONE_SECOND_IN_NS,	// thread timeout
		ONE_SECOND_IN_NS);});	// thread table scan time

	EXPECT_TRUE(sleep_caught);
}

TEST_F(sys_call_test, forking_execve)
{
	int callnum = 0;
	int ptid;	// parent tid
	int ctid;	// child tid
	char bcwd[1024];

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
		ctid = fork();

		if(ctid >= 0) // fork succeeded
		{
			if(ctid == 0) // fork() returns 0 to the child process
			{
				char *eargv[] = { (char*)"/bin/echo", (char*)"", (char*)"aa", (char*)"", (char*)"bb", NULL };
				char *eenvp[] = { NULL };

				execve("/bin/echo/", eargv, eenvp);
				execve("/bin/echo", eargv, eenvp);

				sleep(1);

				_exit(0);
			}
			else // fork() returns new pid to the parent process
			{
				ptid = getpid();

				sleep(1);

				wait(&status);	// wait for child to exit, and store its status
								// Use WEXITSTATUS to validate status.
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
		if(e->get_type() == PPME_SYSCALL_EXECVE_15_E)
		{
			//
			// The child should exist
			//
			sinsp_threadinfo* ti = param.m_inspector->get_thread(ctid, false, true);
			EXPECT_EQ("test", ti->get_comm());
			EXPECT_NE((uint64_t) 0, ti->m_vmsize_kb);
			EXPECT_NE((uint64_t) 0, ti->m_vmrss_kb);
			callnum++;
		}
		else if(e->get_type() == PPME_SYSCALL_EXECVE_15_X)
		{
			if(callnum == 1)
			{
				sinsp_threadinfo* ti = param.m_inspector->get_thread(ctid, false, true);
				EXPECT_EQ("test", ti->get_comm());
				EXPECT_GE(0, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("", e->get_param_value_str("exe"));
				EXPECT_EQ("", e->get_param_value_str("args"));
			}
			else
			{
				sinsp_threadinfo* ti = param.m_inspector->get_thread(ctid, false, true);
				EXPECT_EQ("echo", ti->get_comm());
				EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("/bin/echo", e->get_param_value_str("exe"));
				EXPECT_EQ((size_t)4, ti->m_args.size());
				EXPECT_EQ("", ti->m_args[0]);
				EXPECT_EQ("aa", ti->m_args[1]);
				EXPECT_EQ("", ti->m_args[2]);
				EXPECT_EQ("bb", ti->m_args[3]);

				string tmps = getcwd(bcwd, 1024);
				EXPECT_EQ(tmps, e->get_param_value_str("cwd"));
			}
			
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, callnum);
}

///////////////////////////////////////////////////////////////////////////////
// CLONE VARIANTS
///////////////////////////////////////////////////////////////////////////////
int ctid;	// child tid

typedef struct 
{
    int    fd;
    int    signal;
} clone_params;

static int clone_callback_1(void *arg)
{
    clone_params *cp;

    cp = (clone_params *) arg;   /* Cast arg to true form */
	ctid = getpid();
    close(cp->fd);
    return 0;
}

TEST_F(sys_call_test, forking_clone_fs)
{
	int callnum = 0;
	char bcwd[1024];
	int prfd;
	int ptid;	// parent tid
	int flags = CLONE_FILES | CLONE_FS | CLONE_VM;
	int drflags = PPM_CL_CLONE_FILES | PPM_CL_CLONE_FS | PPM_CL_CLONE_VM;

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
		const int STACK_SIZE = 65536;       /* Stack size for cloned child */
		char *stack;                        /* Start of stack buffer area */
		char *stackTop;                     /* End of stack buffer area */
		clone_params cp;                     /* Passed to child function */
		int status;
		pid_t pid;

		ptid = getpid();

		/* Set up an argument structure to be passed to cloned child, and
		   set some process attributes that will be modified by child */

		cp.fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);  /* Child will close this fd */
		if (cp.fd == -1)
		    FAIL();
		prfd = cp.fd;

		cp.signal = SIGTERM;                /* Child will change disposition */
		if (signal(cp.signal, SIG_IGN) == SIG_ERR)
		    FAIL();

		/* Initialize clone flags using command-line argument (if supplied) */


		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
		    FAIL();
		stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		if (clone(clone_callback_1, stackTop, flags, &cp) == -1)
		    FAIL();

		/* Parent falls through to here. Wait for child; __WCLONE option is
		   required for child notifying with signal other than SIGCHLD. */

		pid = waitpid(-1, &status, __WCLONE);
		if (pid == -1)
		    FAIL();

		close(cp.fd);

		sleep(1);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			uint64_t res = NumberParser::parse64(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->get_comm() != "test")
			{
				return;
			}

			if(res == 0)
			{
				EXPECT_EQ(ctid, ti->m_tid);				
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);				
			}

			EXPECT_EQ("./test", e->get_param_value_str("exe"));				
			EXPECT_EQ("test", ti->get_comm());				
			string tmps = getcwd(bcwd, 1024);
			EXPECT_EQ(tmps, e->get_param_value_str("cwd"));
			EXPECT_EQ(drflags, NumberParser::parse(e->get_param_value_str("flags", false)));
			callnum++;
		}
		else if(e->get_type() == PPME_SYSCALL_CLOSE_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->m_tid == ptid || ti->m_tid == ctid)
			{
				int64_t clfd = NumberParser::parse64(e->get_param_value_str("fd", false));

				if(clfd == prfd)
				{
					callnum++;
				}
			}
		}
		else if(e->get_type() == PPME_SYSCALL_CLOSE_X)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(callnum < 3)
			{
				return;
			}

			int64_t res = NumberParser::parse64(e->get_param_value_str("res", false));

			if(ti->m_tid == ptid)
			{
				EXPECT_GT(0, res);
			}
			else if(ti->m_tid == ctid)
			{
				EXPECT_EQ(0, res);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(6, callnum);
}

TEST_F(sys_call_test, forking_clone_nofs)
{
	int callnum = 0;
	char bcwd[1024];
	int prfd;
	int ptid;	// parent tid
	int flags = CLONE_FS | CLONE_VM;
	int drflags = PPM_CL_CLONE_FS | PPM_CL_CLONE_VM;

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
		const int STACK_SIZE = 65536;       /* Stack size for cloned child */
		char *stack;                        /* Start of stack buffer area */
		char *stackTop;                     /* End of stack buffer area */
		clone_params cp;                     /* Passed to child function */
		int status;
		pid_t pid;

		ptid = getpid();

		/* Set up an argument structure to be passed to cloned child, and
		   set some process attributes that will be modified by child */

		cp.fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);  /* Child will close this fd */
		if (cp.fd == -1)
		    FAIL();
		prfd = cp.fd;

		cp.signal = SIGTERM;                /* Child will change disposition */
		if (signal(cp.signal, SIG_IGN) == SIG_ERR)
		    FAIL();

		/* Initialize clone flags using command-line argument (if supplied) */


		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
		    FAIL();
		stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		if (clone(clone_callback_1, stackTop, flags, &cp) == -1)
		    FAIL();

		/* Parent falls through to here. Wait for child; __WCLONE option is
		   required for child notifying with signal other than SIGCHLD. */

		pid = waitpid(-1, &status, __WCLONE);
		if (pid == -1)
		    FAIL();

		close(cp.fd);

		sleep(1);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			uint64_t res = NumberParser::parse64(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->get_comm() != "test")
			{
				return;
			}

			if(res == 0)
			{
				EXPECT_EQ(ctid, ti->m_tid);				
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);				
			}

			EXPECT_EQ("./test", e->get_param_value_str("exe"));				
			EXPECT_EQ("test", ti->get_comm());				
			string tmps = getcwd(bcwd, 1024);
			EXPECT_EQ(tmps, e->get_param_value_str("cwd"));
			EXPECT_EQ(drflags, NumberParser::parse(e->get_param_value_str("flags", false)));
			callnum++;
		}
		else if(e->get_type() == PPME_SYSCALL_CLOSE_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->m_tid == ptid || ti->m_tid == ctid)
			{
				int64_t clfd = NumberParser::parse64(e->get_param_value_str("fd", false));

				if(clfd == prfd)
				{
					callnum++;
				}
			}
		}
		else if(e->get_type() == PPME_SYSCALL_CLOSE_X)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(callnum < 3)
			{
				return;
			}

			int64_t res = NumberParser::parse64(e->get_param_value_str("res", false));

			if(ti->m_tid == ptid)
			{
				EXPECT_EQ(0, res);
			}
			else if(ti->m_tid == ctid)
			{
				EXPECT_EQ(0, res);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(6, callnum);
}

static int clone_callback_2(void *arg)
{
	char bcwd[256];

	chdir("/");
	string tmps = getcwd(bcwd, 256);
    syscall(SYS_exit);
    return -1;
}

TEST_F(sys_call_test, forking_clone_cwd)
{
	int callnum = 0;
	char oriwd[1024];
	char bcwd[256];
	int ptid;	// parent tid
	int flags = CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD;
	int drflags = PPM_CL_CLONE_VM|PPM_CL_CLONE_FS|PPM_CL_CLONE_FILES|PPM_CL_CLONE_SIGHAND|PPM_CL_CLONE_THREAD;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == ptid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		const int STACK_SIZE = 65536;       /* Stack size for cloned child */
		char *stack;                        /* Start of stack buffer area */
		char *stackTop;                     /* End of stack buffer area */
		clone_params cp;                     /* Passed to child function */

		ptid = getpid();

		getcwd(oriwd, 1024);

		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
		    FAIL();
		stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		if (clone(clone_callback_2, stackTop, flags, &cp) == -1)
		{
		    FAIL();			
		}

		sleep(1);

		string tmps = getcwd(bcwd, 256);

		chdir(oriwd);

		sleep(1);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			uint64_t res = NumberParser::parse64(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);
			if(ti->get_comm() != "test")
			{
				return;
			}

			if(res == 0)
			{
				EXPECT_EQ(ctid, ti->m_tid);				
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);				
			}

			EXPECT_EQ("./test", e->get_param_value_str("exe"));				
			EXPECT_EQ("test", ti->get_comm());				
			EXPECT_EQ(drflags, NumberParser::parse(e->get_param_value_str("flags", false)));
			callnum++;
		}
		else if(e->get_type() == PPME_SYSCALL_GETCWD_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->m_tid == ptid)
			{
				if(callnum > 1)
				{
					EXPECT_EQ(bcwd, ti->get_cwd());
				}
			}
			else if(ti->m_tid == ctid)
			{
				EXPECT_EQ("/", ti->get_cwd());
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(3, callnum);
}

#if 0
TEST_F(sys_call_test, forking_clone_nocwd)
{
	int callnum = 0;
	char bcwd[1024];
	int ptid;	// parent tid
	int flags = CLONE_VM;
	int drflags = PPM_CL_CLONE_VM;

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
		const int STACK_SIZE = 65536;       /* Stack size for cloned child */
		char *stack;                        /* Start of stack buffer area */
		char *stackTop;                     /* End of stack buffer area */
		clone_params cp;                     /* Passed to child function */
		int status;
		pid_t pid;

		ptid = getpid();

		/* Allocate stack for child */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
		    FAIL();
		stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

		/* Create child; child commences execution in childFunc() */

		if (clone(clone_callback_2, stackTop, flags, &cp) == -1)
		    FAIL();

		/* Parent falls through to here. Wait for child; __WCLONE option is
		   required for child notifying with signal other than SIGCHLD. */

		pid = waitpid(-1, &status, __WCLONE);
		if (pid == -1)
		    FAIL();

		string tmps = getcwd(bcwd, 256);

		sleep(1);
		exit(0);		
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SYSCALL_CLONE_X)
		{
			uint64_t res = NumberParser::parse64(e->get_param_value_str("res", false));
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->get_comm() != "test")
			{
				return;
			}

			if(res == 0)
			{
				EXPECT_EQ(ctid, ti->m_tid);				
			}
			else
			{
				EXPECT_EQ(ptid, ti->m_tid);				
			}

			EXPECT_EQ("./test", e->get_param_value_str("exe"));				
			EXPECT_EQ("test", ti->get_comm());				
			EXPECT_EQ(drflags, NumberParser::parse(e->get_param_value_str("flags", false)));
			callnum++;
		}
		else if(e->get_type() == PPME_SYSCALL_GETCWD_E)
		{
			sinsp_threadinfo* ti = e->get_thread_info(false);

			if(ti->m_tid == ptid)
			{
				EXPECT_EQ(string(bcwd) + "/", ti->get_cwd());
			}
			else if(ti->m_tid == ctid)
			{
				EXPECT_EQ("/", ti->get_cwd());
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, callnum);
}
#endif

TEST_F(sys_call_test, forking_main_thread_exit)
{
	int callnum = 0;
	int fd;
	pid_t cpid;	// parent tid

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* ti = evt->get_thread_info();
		if(ti)
		{
			return ti->m_pid == cpid;
		}
		else
		{
			return false;
		}
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		int status;

		// ptid = getpid();

		cpid = fork();
		EXPECT_NE(-1, cpid);
		if(cpid == 0)
		{
			execlp("resources/forking_main_thread_exit", "resources/forking_main_thread_exit", NULL);
			perror("execlp");
			FAIL();
		}
		else
		{
			//
			// Father, just wait for termination
			//
			wait(&status);
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if(param.m_evt->get_type() == PPME_SYSCALL_OPEN_X)
		{
			if(param.m_evt->get_param_value_str("name") == "/etc/passwd")
			{
				EXPECT_EQ("<f>/etc/passwd", param.m_evt->get_param_value_str("fd"));
				fd = *(int64_t *)param.m_evt->get_param(0)->m_val;
				++callnum;
			}
		}
		else if(param.m_evt->get_type() == PPME_PROCEXIT_1_E && param.m_evt->get_tid() == cpid)
		{
			++callnum;
		}
		else if(param.m_evt->get_type() == PPME_SYSCALL_READ_E)
		{
			if(*(int64_t *)param.m_evt->get_param(0)->m_val == fd)
			{
				EXPECT_EQ("<f>/etc/passwd", param.m_evt->get_param_value_str("fd"));
				++callnum;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(3, callnum);
}
