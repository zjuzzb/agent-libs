
#include <gtest.h>
#include "configuration.h"
#include "watchdog_runnable.h"
#include "watchdog_runnable_pool.h"

namespace {

class never_heartbeat_runnable : public dragent::watchdog_runnable
{
public:
	never_heartbeat_runnable() :
	   dragent::watchdog_runnable("never-heartbeat")
	{
	}

	// promote
	using dragent::watchdog_runnable::heartbeat;

private:
	void do_run() override
	{
	}
};

} // anonymous namespace

TEST(watchdog_runnable_test, timeout)
{
	dragent_configuration::m_terminate = false;

	uint64_t timeout_s = 1;

	never_heartbeat_runnable thread1;

	dragent::watchdog_runnable_pool pool;
	pool.start(thread1, timeout_s);

	thread1.heartbeat();

	auto unhealthy = pool.unhealthy_runnables();
	ASSERT_TRUE(unhealthy.empty());

	Poco::Thread::sleep(static_cast<int>(timeout_s * 2) * 1000);

	unhealthy = pool.unhealthy_runnables();
	ASSERT_TRUE(!unhealthy.empty());

	if(!unhealthy.empty())
	{
		const dragent::watchdog_runnable_pool::hung_runnable& dead_thread = unhealthy[0];
		ASSERT_EQ(&dead_thread.hung, static_cast<dragent::watchdog_runnable *>(&thread1));
		ASSERT_GE(dead_thread.since_last_heartbeat_ms, timeout_s);
	}

	Poco::ThreadPool::defaultPool().joinAll();
}
