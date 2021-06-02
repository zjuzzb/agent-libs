#pragma once

#include "timer-wheel.h"
#include "running_state_runnable.h"
#include <utils.h>
#include <utility>

typedef std::function<void()> Callback;

/**
 * @brief A timer thread that can have events scheduled to run
 * after a timeout elapses.
 *
 * To run a closure in 5 seconds, do something like this:
 *
 *    auto timer = TimerEvent<Callback>([]() {
 *        LOG_DEBUG("Five seconds elapsed!");
 *    });
 *    timer_thread->schedule(timer, 5000);
 *
 * Freeing the TimerEvent cancels the timer, so you need
 * to store it somewhere until it fires ot you no longer
 * want it to fire.
 */
class timer_thread: public dragent::running_state_runnable
{
private:
	static constexpr const uint64_t NS_PER_MS = 1000 * 1000;

public:
	explicit timer_thread(uint64_t tick_interval_ms=1000):
		running_state_runnable("timer_thread"),
		m_tick_interval_ms(tick_interval_ms),
		m_prev_time(sinsp_utils::get_current_time_ns() / NS_PER_MS)
	{}

	/**
	 * @brief Call the callback contained in `event`, `delta_ns` nanoseconds
	 *        in the future
	 *
	 * @param event a callback object, generally obtained from
	 *        `TimerEvent<Callback>(closure)`
	 *
	 * @param delta_ns relative time (in nanoseconds) to call the callback,
	 *        converted to milliseconds immediately.
	 *
	 * Due to simplistic implementation, it's not suited for short
	 * and precise timeouts (when the timer thread is idle, the first
	 * callback may run up to `m_tick_interval_ms` msec late.
	 */
	inline void schedule(TimerEventInterface* event, Tick delta_ns)
	{
		// ns to ms
		m_timer_wheel.schedule(event, delta_ns / NS_PER_MS);
	}

	void do_run() override;

private:
	const uint64_t m_tick_interval_ms;
	uint64_t m_prev_time;
	TimerWheel m_timer_wheel;
};
