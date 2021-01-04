#include <gtest.h>
#include <command_line_runnable.h>
#include <scoped_config.h>
#include <watchdog_runnable_pool.h>
#include <atomic>

namespace 
{

/**
 * Reset the command line manager after every test.
 */
class command_line_runnable_test : public testing::Test
{
public: 
	command_line_runnable_test() 
	{
	}

	void TearDown() override
	{
		command_line_manager::instance().clear();
	}
};

/**
 * Simple running state for runnable under test
 */
class test_running_state
{
public:
	test_running_state() : m_terminated(false)
	{}

	void terminate()
	{
		m_terminated = true;
	}

	bool m_terminated = false;

	bool is_terminated() { return m_terminated; }
};

// The class under test with a terminate delegate
class test_command_line_runnable : public command_line_runnable
{
public:
	test_command_line_runnable() : command_line_runnable(std::bind(&test_running_state::is_terminated, &m_state))
	{}

	test_running_state m_state;
};

} // namespace

// Ensure that the runnable accepts commands, calls the command_line_manager and
// calls back with the appropriate data
TEST_F(command_line_runnable_test, basic)
{
	// Reduce the timeout so the runnable terminates faster
	test_helpers::scoped_config<int> interval("command_line.async_heartbeat_timeout_ms", 100);

	test_command_line_runnable cmdline;

	watchdog_runnable_pool pool;
	pool.start(cmdline, watchdog_runnable::NO_TIMEOUT);

	while (!cmdline.is_started())
	{
		Poco::Thread::sleep(10);
	}

	{
		command_line_manager::command_info cmd;
		cmd.handler = [](const command_line_manager::argument_list &args) { return "hi";};
		command_line_manager::instance().register_command("hello", cmd);
	}
	{
		command_line_manager::command_info cmd;
		cmd.handler = [](const command_line_manager::argument_list &args) { return "later";};
		command_line_manager::instance().register_command("goodbye", cmd);
	}

	std::atomic<int> count;
	count = 0;
	auto validate_hi = [&count](const command_line_manager::response& resp)
	{
		ASSERT_EQ(command_line_manager::content_type::TEXT, resp.first);
		ASSERT_EQ("hi", resp.second);
		++count;
	};

	auto validate_bye = [&count](const command_line_manager::response& resp)
	{
		ASSERT_EQ(command_line_manager::content_type::TEXT, resp.first);
		ASSERT_EQ("later", resp.second);
		++count;
	};

	cmdline.async_handle_command("hello", validate_hi);
	cmdline.async_handle_command("goodbye", validate_bye);

	// Wait for both validate functions to get called
	while (count < 2)
	{
		Poco::Thread::sleep(10);
	}

	cmdline.m_state.terminate();

	// Lambdas should have validated the data but check the count to make
	// sure they were called.
	ASSERT_EQ(2, count);

	cmdline.m_state.terminate();
	Poco::ThreadPool::defaultPool().joinAll();
}

