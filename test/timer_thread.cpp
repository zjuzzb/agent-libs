#include <analyzer_utils.h>
#include <watchdog_runnable_pool.h>
#include <timer_thread.h>

#include <gtest.h>

static constexpr const uint64_t NS_PER_MS = 1000 * 1000;

TEST(timer_thread_test, basic)
{
	dragent::running_state::instance().reset_for_test();
	watchdog_runnable_pool pool;
	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>(50);
	bool fired = false;

	pool.start(the_timer_thread, 10);

	TimerEvent<Callback> event([&]() {
		fired = true;
	});

	the_timer_thread->schedule(&event, 100 * NS_PER_MS);

	usleep(100 * 1000);

	dragent::running_state::instance().shut_down();
	pool.stop_all();
	ASSERT_TRUE(fired);
}

TEST(timer_thread_test, cancel)
{
	dragent::running_state::instance().reset_for_test();
	watchdog_runnable_pool pool;
	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>(50);
	bool fired = false;

	pool.start(the_timer_thread, 10);

	TimerEvent<Callback> event([&]() {
		fired = true;
	});

	the_timer_thread->schedule(&event, 1000 * NS_PER_MS);
	event.cancel();

	usleep(100 * 1000);

	dragent::running_state::instance().shut_down();
	pool.stop_all();
	ASSERT_TRUE(!fired);
}

TEST(timer_thread_test, via_unique_ptr)
{
	dragent::running_state::instance().reset_for_test();
	watchdog_runnable_pool pool;
	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>(50);
	bool fired = false;

	pool.start(the_timer_thread, 10);

	std::unique_ptr<TimerEvent<Callback>> event;
	event = make_unique<TimerEvent<Callback>>([&]() {
		fired = true;
	});

	the_timer_thread->schedule(event.get(), 100 * NS_PER_MS);

	usleep(1000 * 1000);

	dragent::running_state::instance().shut_down();
	pool.stop_all();
	ASSERT_TRUE(fired);
}

TEST(timer_thread_test, free_before_fire)
{
	dragent::running_state::instance().reset_for_test();
	watchdog_runnable_pool pool;
	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>(50);
	bool fired = false;

	pool.start(the_timer_thread, 10);

	std::unique_ptr<TimerEvent<Callback>> event(new TimerEvent<Callback>([&]() {
		fired = true;
	}));

	the_timer_thread->schedule(event.get(), 1000 * NS_PER_MS);
	event = nullptr;

	usleep(100 * 1000);

	dragent::running_state::instance().shut_down();
	pool.stop_all();
	ASSERT_TRUE(!fired);
}

TEST(timer_thread_test, free_self)
{
	dragent::running_state::instance().reset_for_test();
	watchdog_runnable_pool pool;
	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>(50);
	bool fired = false;

	pool.start(the_timer_thread, 10);

	std::unique_ptr<TimerEvent<Callback>> event;
	event = make_unique<TimerEvent<Callback>>([&]() {
		fired = true;
		event = nullptr;
	});

	the_timer_thread->schedule(event.get(), 100 * NS_PER_MS);

	usleep(1000 * 1000);

	dragent::running_state::instance().shut_down();
	pool.stop_all();
	ASSERT_TRUE(fired);
}

TEST(timer_thread_test, free_unique_ptr)
{
	dragent::running_state::instance().reset_for_test();
	watchdog_runnable_pool pool;
	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>(50);
	bool fired = false;

	pool.start(the_timer_thread, 10);

	std::unique_ptr<TimerEvent<Callback>> event;
	event = make_unique<TimerEvent<Callback>>([&]() {
		fired = true;
		event = nullptr;
	});

	the_timer_thread->schedule(event.get(), 100 * NS_PER_MS);
	event = nullptr;

	usleep(1000 * 1000);

	dragent::running_state::instance().shut_down();
	pool.stop_all();
	ASSERT_TRUE(!fired);
}
