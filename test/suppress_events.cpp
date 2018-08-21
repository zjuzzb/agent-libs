#include <thread>
#include <memory>

#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/quota.h>

#include <gtest.h>

#include "sys_call_test.h"
#include "event_capture.h"

struct test_helper_args
{
	bool start_before;
	bool suppress_before;
	bool spawn_with_bash;
};

static void test_helper_quotactl(test_helper_args &hargs)
{
	// We start the test_helper process before starting the
	// capture, so the initial proc scan will see the pid. Once
	// the capture has started we let the test_helper process
	// perform its work.
	pid_t pid = getpid();
	bool test_helper_done = false;

	proc test_proc = proc("./test_helper", { "threaded", "quotactl_ko"});

	if(hargs.spawn_with_bash)
	{
		test_proc = proc("./test_helper.sh", {"threaded", "quotactl_ko"});
	}

	std::shared_ptr<Poco::ProcessHandle> test_helper_h;
	Poco::Pipe *test_helper_stdin;
	int64_t test_helper_pid = 0;

	if(hargs.start_before)
	{
		auto test_proc_handle = start_process_sync(&test_proc);
		test_helper_h = make_shared<Poco::ProcessHandle>(get<0>(test_proc_handle));
		test_helper_stdin = get<1>(test_proc_handle);
		delete get<2>(test_proc_handle);
		test_helper_pid = test_helper_h->id();
	}

	//
	// Access/modify inspector before opening
	//

	before_open_t before_open = [&](sinsp *inspector)
	{
		if(hargs.suppress_before)
		{
			inspector->suppress_events_comm(string((hargs.spawn_with_bash ? "test_helper.sh" : "test_helper")));
		}
	};

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return (evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
			evt->get_type() == PPME_PROCEXIT_1_E);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		if(!hargs.suppress_before)
		{
			inspector->suppress_events_comm(string((hargs.spawn_with_bash ? "test_helper.sh" : "test_helper")));
		}

		if(!hargs.start_before)
		{
			auto test_proc_handle = start_process_sync(&test_proc);
			test_helper_h = make_shared<Poco::ProcessHandle>(get<0>(test_proc_handle));
			test_helper_stdin = get<1>(test_proc_handle);
			delete get<2>(test_proc_handle);
			test_helper_pid = test_helper_h->id();
		}

		// Send a message to test_helper. This instructs it to continue.
		test_helper_stdin->writeBytes("START", 5);

		// Wait for it to finish
		test_helper_h->wait();

		// Do a quotactl--when the callback loop sees this,
		// it's an indication that all the relevant events
		// have been received.
		quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* evt = param.m_evt;

		switch(evt->get_type())
		{
		case PPME_SYSCALL_QUOTACTL_X:
			if(evt->get_tid() != pid)
			{
				FAIL() << "Should not have observed any quotactl event";
			}
			else
			{
				test_helper_done=true;
			}
			break;
		case PPME_PROCEXIT_1_E:
			ASSERT_FALSE(param.m_inspector->check_suppressed(evt->get_tid()));
			break;
		}
	};

	capture_continue_t should_continue = [&]()
	{
		return (!test_helper_done);
	};

	before_close_t before_close = [](sinsp *inspector)
	{
		scap_stats st;

		inspector->get_capture_stats(&st);

		ASSERT_GT(st.n_suppressed, 0u);
		ASSERT_EQ(st.n_tids_suppressed, 0u);
	};

	// We increase the number of timeouts to 1k (~30 seconds, if
	// there were no SCAP_TIMEOUTS other than the ones from the
	// capture buffer being empty) to address the additional
	// timeouts from suppressed events. In normal testing,
	// should_continue() should cause the test to stop as soon as
	// we see the procexit for the spawned process.
	sinsp_configuration configuration;

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, configuration,
						    NULL, 0, 0, 0,
						    SCAP_MODE_LIVE, before_open, before_close, should_continue, 1000);});
	delete test_helper_stdin;
}

TEST_F(sys_call_test, suppress_existing_process)
{
	test_helper_args hargs;
	hargs.start_before = true;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_new_process)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}

TEST_F(sys_call_test, suppress_add_new_value_while_running)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = false;
	hargs.spawn_with_bash = false;

	test_helper_quotactl(hargs);
}


TEST_F(sys_call_test, suppress_grandchildren)
{
	test_helper_args hargs;
	hargs.start_before = false;
	hargs.suppress_before = true;
	hargs.spawn_with_bash = true;

	test_helper_quotactl(hargs);
}

class suppress_types : public sys_call_test
{
protected:
	static bool is_target_call(uint16_t type);
	void do_syscalls();
	bool is_suppressed(uint16_t type) const;
	void run_test(vector<string> supp_types);

	vector<uint16_t> m_suppressed_types;
	int m_expected_calls;
};

bool suppress_types::is_target_call(uint16_t type)
{
	switch(type)
	{
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X:
	case PPME_SYSCALL_GETRLIMIT_E:
	case PPME_SYSCALL_GETRLIMIT_X:
		return true;
		break;
	}
	return false;
}

void suppress_types::do_syscalls()
{
	struct rlimit limits;
	getrlimit(RLIMIT_AS, &limits);
	fcntl(1, F_GETFD);

	// enter+exit for 2 syscalls
	m_expected_calls = 4;
	for (const auto ii : m_suppressed_types)
	{
		if (is_target_call(ii))
		{
			m_expected_calls--;
		}
	}

}

bool suppress_types::is_suppressed(uint16_t type) const
{
	for (const auto ii : m_suppressed_types)
	{
		if (type == ii)
		{
			return true;
		}
	}

	return false;
}

void suppress_types::run_test(vector<string> supp_types)
{
	sinsp_utils::parse_suppressed_types(supp_types, &m_suppressed_types);
	int callnum = 0;

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		for (auto type : m_suppressed_types)
		{
			bool expect_exception = (type >= PPM_EVENT_MAX);
			bool caught_exception = false;

			try
			{
				inspector->unset_eventmask(type);
			}
			catch (sinsp_exception& e)
			{
				caught_exception = true;
			}

			ASSERT_EQ(expect_exception, caught_exception);
		}

		do_syscalls();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		auto type = param.m_evt->get_type();
		EXPECT_FALSE(is_suppressed(type));
		if (is_target_call(type))
		{
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, m_tid_filter);});
	EXPECT_EQ(m_expected_calls, callnum);
}

TEST_F(suppress_types, block_getrlimit)
{
	// PPME_SYSCALL_GETRLIMIT_(E|X)
	ASSERT_NO_FATAL_FAILURE(run_test({"getrlimit"}));
}

TEST_F(suppress_types, block_fcntl)
{
	// PPME_SYSCALL_FCNTL_(E|X)
	ASSERT_NO_FATAL_FAILURE(run_test({"fcntl"}));
}

TEST_F(suppress_types, block_getrlimit_and_fcntl)
{
	// PPME_SYSCALL_GETRLIMIT_(E|X) && PPME_SYSCALL_FCNTL_(E|X)
	ASSERT_NO_FATAL_FAILURE(run_test({"getrlimit", "fcntl"}));
}

TEST_F(suppress_types, block_none)
{
	ASSERT_NO_FATAL_FAILURE(run_test({}));
}

TEST_F(suppress_types, block_nonexistent_call)
{
	ASSERT_NO_FATAL_FAILURE(run_test({"notarealname"}));
}
