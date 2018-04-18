// General test:
// - fork a child, start a new session
// - fork a grandchild
//   - Have the grandchild change to its own process group and then
//     exec a test program.
//   - In the test program, have the grandchild change back to the
//     child's process group and then exec
//     This is doing with a pid-specific first arg to getpgid().
// This is done twice, once in the global pid namespace and once in a
// new namespace.

#include "sys_call_test.h"
#include <gtest.h>

#include <sinsp.h>

static int clone_callback(void *arg)
{
	// Start a new session. This also creates a new process group.
	pid_t sid = setsid();

	if(sid == -1)
	{
		fprintf(stderr, "Can't call setsid(): %s\n", strerror(errno));
		return -1;
	}
	pid_t pgid = getpgid(0);

	int gchild_pid = fork();

	if(gchild_pid == 0)
	{
		// Grandchild

		// Change to own process group
		int rc = setpgid(0, 0);
		if(rc != 0)
		{
			fprintf(stderr, "Can't call setpgid(): %s\n", strerror(errno));
			return -1;
		}

		char *const exargs[] = {(char *) "./test_helper", (char *) "pgid_test", (char *) std::to_string(pgid).c_str(), nullptr};
		char *const exenv[] = {nullptr};
		if ((rc = execve("./test_helper", exargs, exenv)) != 0)
		{
			fprintf(stderr, "Can't exec \"./test_helper pgid_test\": %s\n", strerror(errno));
			return -1;
		}

		return 0;
	}
	else
	{
		int status;
		if (waitpid(gchild_pid, &status, 0) != gchild_pid)
		{
			fprintf(stderr, "Can't call waitpid(): %s\n", strerror(errno));
			return -1;

			if(WEXITSTATUS(status) != 0)
			{
				fprintf(stderr, "Grandchild exited with non-zero status %d\n", WEXITSTATUS(status));
				return -1;
			}
		}
	}
	return 0;
}

static void run_setpgid_test(bool use_pid_namespace)
{
	int callnum = 0;
	int child_pid = 0;

	//
	// FILTER
	//
	sinsp_filter_compiler compiler(NULL, "evt.type=execve and proc.apid=" + to_string(getpid()));
	unique_ptr<sinsp_filter> is_subprocess_setpgid(compiler.compile());
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return is_subprocess_setpgid->run(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int stack_size = 65536;
		char *stack;
		char *stack_top;
		int flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD;

		if(use_pid_namespace)
		{
			flags |= CLONE_NEWPID;
		}

		stack = (char*) malloc(stack_size);
		if (stack == NULL)
		{
		    FAIL();
		}
		stack_top = stack + stack_size;

		if ((child_pid = clone(clone_callback, stack_top, flags, NULL)) == -1)
		{
		    FAIL();
		}

		int status;
		ASSERT_EQ(waitpid(child_pid, &status, 0), child_pid);
		ASSERT_EQ(WEXITSTATUS(status), 0);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		// We expect to see the following events:
		//   - first exexce(), after first setpgid: verify that (grand)child's threadinfo is in own process group.
		//   - second setpgid(), after second setpgid: verify that (grand)child has moved back to child's process group.

		if(type == PPME_SYSCALL_EXECVE_19_X)
		{
			if(callnum == 0)
			{
				sinsp_threadinfo *tinfo = e->get_thread_info();

				ASSERT_TRUE(tinfo->m_vpgid == tinfo->m_vpid);
				callnum++;
			}
			else if(callnum == 1)
			{
				sinsp_threadinfo *tinfo = e->get_thread_info();

				// If the child was run in a new pid
				// namespace, it's pid is assumed to
				// be 1.
				ASSERT_TRUE(tinfo->m_vpgid == (use_pid_namespace ? 1 : child_pid));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
}

TEST_F(sys_call_test, setpgid)
{
	run_setpgid_test(false);
}

TEST_F(sys_call_test, setpgid_pid_namespace)
{
	run_setpgid_test(true);
}
