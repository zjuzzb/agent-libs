#include <atomic>
#include <exception>
#include <gtest.h>
#include "configuration.h"
#include "common_logger.h"
#include "watchdog_runnable.h"
#include "watchdog_runnable_fatal_error.h"
#include "watchdog_runnable_pool.h"

COMMON_LOGGER();

using namespace dragent;

namespace {

class test_runnable : public watchdog_runnable
{
public:
	test_runnable() :
	   watchdog_runnable("test_runnable"),
	   m_continue(true),
	   m_hijinks(false)
	{
	}

	std::atomic<bool> m_continue;
	std::atomic<bool> m_hijinks;

private:
	void do_run() override
	{
		while (heartbeat() && m_continue)
		{
			if(m_hijinks)
			{
				THROW_DRAGENT_WR_FATAL_ERROR("hijinks %d!", 123);
			}

			Poco::Thread::sleep(1);
		}
	}
};

} // anonymous namespace

TEST(watchdog_runnable_test, timeout)
{
	dragent_configuration::m_terminate = false;

	uint64_t timeout_s = 1;

	test_runnable action1;
	// Validate it hasn't started
	ASSERT_FALSE(action1.is_started());

	watchdog_runnable_pool pool;
	pool.start(action1, timeout_s);

	// Wait until it starts
	while (!action1.is_started())
	{
		Poco::Thread::sleep(10);
	}

	// Wait for double the timeout
	Poco::Thread::sleep(static_cast<int>(timeout_s * 2)* 1000);

	// Task should be healthy because the heartbeat is happening
	auto unhealthy = pool.unhealthy_list();
	ASSERT_TRUE(unhealthy.empty());

	// Stop the task and wait double the timeout
	action1.m_continue = false;
	Poco::Thread::sleep(static_cast<int>(timeout_s * 2)* 1000);

	// Validate that the task is unhealthy
	unhealthy = pool.unhealthy_list();
	ASSERT_TRUE(!unhealthy.empty());

	if(!unhealthy.empty())
	{
		const watchdog_runnable_pool::unhealthy_runnable& dead_thread = unhealthy[0];
		ASSERT_EQ(&dead_thread.runnable, static_cast<watchdog_runnable *>(&action1));
		ASSERT_EQ(dead_thread.health, watchdog_runnable::health::TIMEOUT);
		ASSERT_GE(dead_thread.since_last_heartbeat_ms, timeout_s);
	}

	Poco::ThreadPool::defaultPool().joinAll();
}

TEST(watchdog_runnable_test, no_timeout)
{
	dragent_configuration::m_terminate = false;

	test_runnable action1;
	ASSERT_FALSE(action1.is_started());

	watchdog_runnable_pool pool;
	pool.start(action1, watchdog_runnable::NO_TIMEOUT);

	// Wait until it starts
	while (!action1.is_started())
	{
		Poco::Thread::sleep(10);
	}

	Poco::Thread::sleep(20);

	// We're just making sure it doesn't timeout immediately with the
	// 0 timeout
	auto unhealthy = pool.unhealthy_list();
	ASSERT_TRUE(unhealthy.empty());

	action1.m_continue = false;

	Poco::ThreadPool::defaultPool().joinAll();
}

TEST(watchdog_runnable_test, global_terminate)
{
	dragent_configuration::m_terminate = false;

	test_runnable action1;
	ASSERT_FALSE(action1.is_started());

	watchdog_runnable_pool pool;
	pool.start(action1, watchdog_runnable::NO_TIMEOUT);

	while (!action1.is_started())
	{
		Poco::Thread::sleep(10);
	}

	// Set the global terminate, this should cause the heartbeat function
	// to fail and the task will exit
	dragent_configuration::m_terminate = true;

	// This will wait until all tasks are complete so if this function
	// ever exits then the test passes
	Poco::ThreadPool::defaultPool().joinAll();
}

TEST(watchdog_runnable_test, fatal)
{
	dragent_configuration::m_terminate = false;

	test_runnable action1;

	watchdog_runnable_pool pool;
	pool.start(action1, 1 /*timeout*/);

	while (!action1.is_started())
	{
		Poco::Thread::sleep(10);
	}

	auto unhealthy = pool.unhealthy_list();
	ASSERT_TRUE(unhealthy.empty());

	// This will cause the task to throw a fatal error
	action1.m_hijinks = true;

	// Call join all to wait until thread dies
	Poco::ThreadPool::defaultPool() .joinAll();

	// Validate that the task failed due to a fatal error
	unhealthy = pool.unhealthy_list();
	ASSERT_TRUE(!unhealthy.empty());

	if(!unhealthy.empty())
	{
		const watchdog_runnable_pool::unhealthy_runnable& dead_thread = unhealthy[0];
		ASSERT_EQ(&dead_thread.runnable, static_cast<watchdog_runnable *>(&action1));
		ASSERT_EQ(dead_thread.health, watchdog_runnable::health::FATAL_ERROR);
	}

}

TEST(watchdog_runnable_test, throw_fatal)
{
	try
	{
		THROW_DRAGENT_WR_FATAL_ERROR("uh oh %d!", 77);
		ASSERT_TRUE(false);
	}
	catch (const dragent::watchdog_runnable_fatal_error& ex)
	{
		ASSERT_EQ(std::string("uh oh 77!"), ex.what());
		ASSERT_EQ(std::string("watchdog_runnable.ut"), ex.where());
	}
}
