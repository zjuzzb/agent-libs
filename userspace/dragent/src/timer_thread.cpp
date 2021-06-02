#include <common_logger.h>
#include <common_assert.h>
#include "timer_thread.h"

COMMON_LOGGER();

void timer_thread::do_run()
{
	while(heartbeat())
	{
		unsigned long long next_event_ms = m_timer_wheel.ticks_to_next_event(m_tick_interval_ms);

		struct timespec delay = {
			(long)(next_event_ms / 1000),
			(int)(NS_PER_MS * (next_event_ms % 1000))
		};
		LOG_TRACE("next event in %llu msec (%ld.%06ld sec)",
			 next_event_ms, delay.tv_sec, delay.tv_nsec);

		nanosleep(&delay, nullptr);

		uint64_t now = sinsp_utils::get_current_time_ns() / NS_PER_MS;

		LOG_TRACE("Processing %ld timer ticks", now - m_prev_time);
		m_timer_wheel.advance(now - m_prev_time);
		m_prev_time = now;
	}
}
