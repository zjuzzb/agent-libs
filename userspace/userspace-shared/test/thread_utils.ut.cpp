/**
 * @file
 *
 * Unit tests for namespace thread_utils.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "thread_utils.h"
#include <gtest.h>
#include <thread>
#include <unistd.h>

/**
 * Ensure that in the main thread, the tid and the pid are equal.
 */
TEST(thread_utils_test, main_thread_tid_is_pid)
{
	const pid_t pid = getpid();
	const pid_t tid = thread_utils::get_tid();

	ASSERT_EQ(pid, tid);
}

/**
 * Ensure that in a non-main thread, the tid and the pid differ.
 */
TEST(thread_utils_test, new_thread_tid_is_not_pid)
{
	const pid_t pid = getpid();
	pid_t tid = 0;

	std::thread t([&tid]() { tid = thread_utils::get_tid(); });
	t.join();

	ASSERT_NE(0, tid);
	ASSERT_NE(pid, tid);
}

/**
 * Ensure that for a thread, get_tid() always returns the same value.
 */
TEST(thread_utils_test, new_thread_tid_is_consistent)
{
	pid_t tid1 = 0;
	pid_t tid2 = 0;

	std::thread t([&tid1, &tid2]()
		{
			tid1 = thread_utils::get_tid();
			tid2 = thread_utils::get_tid();
		});
	t.join();

	ASSERT_EQ(tid1, tid2);
}

/**
 * Ensure that different threads have different tids.
 */
TEST(thread_utils_test, different_threads_different_tids)
{
	pid_t tid1 = 0;
	pid_t tid2 = 0;

	std::thread t1([&tid1]() { tid1 = thread_utils::get_tid(); });
	std::thread t2([&tid2]() { tid2 = thread_utils::get_tid(); });

	t1.join();
	t2.join();

	ASSERT_NE(tid1, tid2);
}
