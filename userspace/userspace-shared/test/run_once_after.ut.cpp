/**
 * @file
 *
 * Unit tests for run_once_after.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "run_once_after.h"
#include <gtest.h>

/**
 * Ensure that get_timeout() returns the timeout provided to the constructor.
 */
TEST(run_once_after_test, get_timeout)
{
	const uint64_t time_from_now = 54321;
	const uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };

	userspace_shared::run_once_after runner(54321, clock_source);

	ASSERT_EQ(time_from_now, runner.get_timeout());
}

/**
 * Ensure that get_timeout() returns the timeout provided to the constructor.
 */
TEST(run_once_after_test, set_timeout)
{
	uint64_t time_from_now = 54321;
	const uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };

	userspace_shared::run_once_after runner(54321, clock_source);

	time_from_now *= 2;
	runner.set_timeout(time_from_now);

	ASSERT_EQ(time_from_now, runner.get_timeout());
}

/**
 * Ensure that get_time_to_run() reutrns the current time (as provided by the
 * clock source) plus the given time_from_now_ns.
 */
TEST(run_once_after_test, get_time_to_run_returns_now_plus_time_from_now)
{
	const uint64_t time_from_now = 54321;
	const uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };

	userspace_shared::run_once_after runner(54321, clock_source);

	ASSERT_EQ(time_from_now + now, runner.get_time_to_run());
}

/**
 * Ensure that run() doesn't invoke the given function if the given clock source
 * returns a time that's less than get_time_to_run().
 */
TEST(run_once_after_test, run_does_not_trigger_function_if_time_is_not_up)
{
	const uint64_t time_from_now = 54321;
	uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };
	bool run = false;
	auto run_fn = [&run]() { run = true; };

	userspace_shared::run_once_after runner(54321, clock_source);

	now = now + time_from_now - 1; // 1 ms before it is time

	runner.run(run_fn);

	ASSERT_FALSE(run);
}

/**
 * Ensure that run() invokes the given function if the given clock source
 * returns a time that's equal to get_time_to_run().
 */
TEST(run_once_after_test, run_triggers_function_if_time_is_just_up)
{
	const uint64_t time_from_now = 54321;
	uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };
	bool run = false;
	auto run_fn = [&run]() { run = true; };

	userspace_shared::run_once_after runner(54321, clock_source);

	now = now + time_from_now; // just in time

	runner.run(run_fn);

	ASSERT_TRUE(run);
}

/**
 * Ensure that run() invokes the given function if the given clock source
 * returns a time that's greater than get_time_to_run().
 */
TEST(run_once_after_test, run_triggers_function_if_time_is_past_up)
{
	const uint64_t time_from_now = 54321;
	uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };
	bool run = false;
	auto run_fn = [&run]() { run = true; };

	userspace_shared::run_once_after runner(54321, clock_source);

	now = now + time_from_now + 1; // just after time is up

	runner.run(run_fn);

	ASSERT_TRUE(run);
}

/**
 * Ensure that run() invokes the given function only once after time is up.
 */
TEST(run_once_after_test, run_triggers_function_only_once)
{
	const uint64_t time_from_now = 54321;
	uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };
	bool run = false;
	auto run_fn = [&run]() { run = true; };

	userspace_shared::run_once_after runner(54321, clock_source);

	now = now + time_from_now + 1; // just after time is up

	runner.run(run_fn);

	run = false;
	runner.run(run_fn);

	ASSERT_FALSE(run);
}

/**
 * Ensure that run() invokes the given function only once after time is up
 * (even if during the first run, the function threw an exception).
 */
TEST(run_once_after_test, run_triggers_function_only_once_even_with_exceptions)
{
	const uint64_t time_from_now = 54321;
	uint64_t now = 12345; /* value here is arbitrary */
	auto clock_source = [&now]() { return now; };
	bool run = false;
	auto run_fn = [&run]() { run = true; throw std::string("exception"); };

	userspace_shared::run_once_after runner(54321, clock_source);

	now = now + time_from_now + 1; // just after time is up

	ASSERT_THROW(runner.run(run_fn), std::string);
	ASSERT_TRUE(run);

	run = false;
	ASSERT_NO_THROW(runner.run(run_fn));
	ASSERT_FALSE(run);
}
