#include "common_logger.h"
#include "running_state.h"
#include "timer_thread.h"
#include "watchdog_runnable_pool.h"

#include <gtest.h>
#include <utils.h>
#include <Poco/Condition.h>
#include <Poco/Mutex.h>

COMMON_LOGGER();

TEST(timer_thread, schedule)
{
	Poco::Mutex mtx;
	Poco::Condition cond;
	mtx.lock();

	timer_thread the_timer_thread(200);
	watchdog_runnable_pool m_pool;
	m_pool.start(the_timer_thread, 60);

	// the first event in an empty timer needs a timeout of at least
	// `tick_interval_ms` (the ctor parameter)
	// due to the way we wait for new events to arrive
	uint64_t start = sinsp_utils::get_current_time_ns();

	TimerEvent<Callback> cb([&cond]() {
		LOG_INFO("Callback fired");
		cond.broadcast();
	});

	LOG_INFO("Scheduling callback in 1500 msec");
	the_timer_thread.schedule(&cb, 1500000000);

	cond.wait(mtx);
	LOG_INFO("condition signalled");
	cb.cancel();

	uint64_t end = sinsp_utils::get_current_time_ns();
	int64_t delta_ms = (end - start) / 1000000;
	// 100 ms slack both ways
	ASSERT_GE(delta_ms, 1400);
	ASSERT_LT(delta_ms, 1600);
	dragent::running_state::instance().shut_down();
	m_pool.stop_all();
}
