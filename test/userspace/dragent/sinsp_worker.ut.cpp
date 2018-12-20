#include <gtest.h>
#include "dragent/sinsp_worker.h"

namespace {

uint64_t s_current_ns = 5000000000;
uint64_t current_ns() { return s_current_ns; }

uint64_t s_uptime_ms = 1000;
uint64_t uptime_ms() { return s_uptime_ms; }


uint64_t s_to_ms(float seconds)
{
	return static_cast<uint64_t>(seconds * 1000LL);
}
uint64_t s_to_ns(float seconds)
{
	return static_cast<uint64_t>(seconds * 1000000000LL);
}

}

TEST(sinsp_worker_test, old_events_basic)
{
	int timeout_s = 10;

	// Init the tracker so that we can control the time
	sinsp_worker::old_event_tracker tracker(timeout_s, current_ns, uptime_ms);

	bool ok = tracker.validate(current_ns());
	ASSERT_TRUE(ok);

	// 60 seconds goes by and a event comes in that is 5s old
	s_current_ns += s_to_ns(60);
	s_uptime_ms += s_to_ms(60);
	ok = tracker.validate(current_ns() - s_to_ns(5));
	ASSERT_TRUE(ok);

	// 10 more seconds goes by and now we get an event 14s old which is  our
	// first old event
	s_current_ns += s_to_ns(10);
	s_uptime_ms += s_to_ms(10);
	ok = tracker.validate(current_ns() - s_to_ns(14));
	ASSERT_TRUE(ok);

	// 12 more seconds goes by and we are still getting events older than
	// the 10 seconds timeout
	s_current_ns += s_to_ns(12);
	s_uptime_ms += s_to_ms(12);
	ok = tracker.validate(current_ns() - s_to_ns(11));
	ASSERT_FALSE(ok);
}

TEST(sinsp_worker_test, old_events_reset)
{
	int timeout_s = 10;

	// Init the tracker so that we can control the time
	sinsp_worker::old_event_tracker tracker(timeout_s, current_ns, uptime_ms);

	bool ok = tracker.validate(current_ns());
	ASSERT_TRUE(ok);

	// 20 seconds goes by and now we get an event 14s old which is  our
	// first old event
	s_current_ns += s_to_ns(15);
	s_uptime_ms += s_to_ms(15);
	ok = tracker.validate(current_ns() - s_to_ns(14));
	ASSERT_TRUE(ok);

	// But then after a couple seconds, the events catch up!
	s_current_ns += s_to_ns(2);
	s_uptime_ms += s_to_ms(2);
	ok = tracker.validate(current_ns() - s_to_ns(1));
	ASSERT_TRUE(ok);

	// 12 more seconds goes by and and an old event comes in, but since
	// we've reset already, we should be fine.
	s_current_ns += s_to_ns(12);
	s_uptime_ms += s_to_ms(12);
	ok = tracker.validate(current_ns() - s_to_ns(11));
	ASSERT_TRUE(ok);

	// Go big!
	s_current_ns += s_to_ns(120);
	s_uptime_ms += s_to_ms(120);
	ok = tracker.validate(current_ns() - s_to_ns(11));
	ASSERT_FALSE(ok);
}

TEST(sinsp_worker_test, old_events_time_skew)
{
	int timeout_s = 10;

	// Init the tracker so that we can control the time
	sinsp_worker::old_event_tracker tracker(timeout_s, current_ns, uptime_ms);

	bool ok = tracker.validate(current_ns());
	ASSERT_TRUE(ok);

	// 15 seconds goes by and now we get an event 11s old which is  our
	// first old event
	s_current_ns += s_to_ns(15);
	s_uptime_ms += s_to_ms(15);
	ok = tracker.validate(current_ns() - s_to_ns(11));
	ASSERT_TRUE(ok);

	// 500 seconds go by because the time on the host changed, but only
	// 5 ms have gone by. The old event tracker doesn't trust the host
	// so it will check the uptime
	s_current_ns += s_to_ns(500);
	s_uptime_ms += 5;
	ok = tracker.validate(current_ns() - s_to_ns(14));
	ASSERT_TRUE(ok);

	// When uptime expires, the old event tracker will fail
	s_uptime_ms += s_to_ms(12);
	ok = tracker.validate(current_ns() - s_to_ns(13));
	ASSERT_FALSE(ok);
}

TEST(sinsp_worker_test, old_events_slow_death)
{
	int timeout_s = 10;

	// Init the tracker so that we can control the time
	sinsp_worker::old_event_tracker tracker(timeout_s, current_ns, uptime_ms);

	uint64_t event_ns = current_ns();
	bool ok = tracker.validate(event_ns);
	ASSERT_TRUE(ok);

	int iterations = 0;
	do
	{	// a millisecond goes by
		s_current_ns += 1000000;
		s_uptime_ms += 1;
		// events fall behind by .2 ms
		event_ns += 800000;
		ok = tracker.validate(event_ns);
		iterations++;
	} while(ok);

	// 10 seconds is 50000 iterations (10s * 1000 ms/s * 1/.2 = 50000)
	// So it takes 50000 iterations to get the first old event and then
	// an additional 10 seconds to time out (10000 iterations)
	ASSERT_EQ(iterations, 60001);

}

TEST(sinsp_worker_test, old_events_no_timeout)
{
	int timeout_s = 0;

	// Init the tracker so that we can control the time
	sinsp_worker::old_event_tracker tracker(timeout_s, current_ns, uptime_ms);

	bool ok = tracker.validate(current_ns());
	ASSERT_TRUE(ok);

	// 1 seconds goes by and now we get an event 14s old which is  our
	// first old event
	s_current_ns += s_to_ns(20);
	s_uptime_ms += s_to_ms(20);
	ok = tracker.validate(current_ns() - s_to_ns(14));
	ASSERT_TRUE(ok);

	// 12 more seconds goes by and we are still getting events older than
	// the 10 seconds timeout
	s_current_ns += s_to_ns(12);
	s_uptime_ms += s_to_ms(12);
	ok = tracker.validate(current_ns() - s_to_ns(11));
	// But timeout is 0 so we are fine
	ASSERT_TRUE(ok);
}
