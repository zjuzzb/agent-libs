/**
 * @file
 *
 * Unit test to validate the spinlock class
 */

#include<gtest.h>
#include <list>
#include <thread>
#include <memory>
#include <cstdint>
#include <chrono>
#include <functional>
#include "spinlock.h"


/**
 * Makes sure the lock doesn't deadlock with zero contention.
 */
TEST(spinlock_test, single_thread_test)
{
	const uint32_t num_elems = 10000;
	spinlock lock;
	std::list<int> test_list;

	for(uint32_t i = 0; i < num_elems; ++i)
	{
		lock.lock();
		test_list.push_back(i);
		lock.unlock();
	}
}

/**
 * Makes sure the lock actually works.
 */
TEST(spinlock_test, multi_thread_test)
{
	const uint32_t elems_per_thread = 100000;
	const uint32_t num_threads = 10;
	spinlock lock;
	std::list<uint32_t> test_list;

	bool go = false;

	auto func = [&go, &test_list, &lock](const uint32_t elems, const uint32_t val)
	{
		while(!go)
		{
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		}

		for(uint32_t i = 0; i < elems; ++i)
		{
			lock.lock();
			test_list.push_back(val);
			lock.unlock();
		}
	};

	std::list<std::thread*> thread_list;

	// Spin up threads
	for(uint32_t t = 0; t < num_threads; ++t)
	{
		auto tp = new std::thread(func, elems_per_thread, t);
		thread_list.push_back(tp);
	}

	go = true;

	// Wait for threads to finish
	while(thread_list.size() > 0)
	{
		auto tp = thread_list.front();
		tp->join();
		delete tp;
		thread_list.pop_front();
	}

	// Validate results
	uint32_t buckets[num_threads] = {};
	uint32_t total_elems = 0;
	for(auto elem: test_list)
	{
		ASSERT_LT(elem, num_threads);
		++buckets[elem];
		++total_elems;
	}

	ASSERT_EQ(total_elems, elems_per_thread * num_threads);
	for(uint32_t i = 0; i < num_threads; ++i)
	{
		ASSERT_EQ(elems_per_thread, buckets[i]);
	}
}

/**
 * Makes sure the scoped version of the lock actually works.
 *
 * In this test, even-numbered workers (and 0) will add elements
 * to the list, while odd-numbered workers will remove them.
 */
TEST(spinlock_test, DISABLED_scoped_multi_thread_test)
{
	const uint32_t elems_per_thread = 10000;
	const uint32_t num_threads = 10;
	spinlock lock;
	std::list<uint32_t> test_list;

	bool go = false;

	std::function<void(const uint32_t, const uint32_t)> add_func = [&go, &test_list, &lock](const uint32_t elems, const uint32_t val)
	{
		while(!go)
		{
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		}

		for(uint32_t i = 0; i < elems; ++i)
		{
			{
				scoped_spinlock l(lock);
				test_list.push_back(val);
			}
		}
	};

	std::function<void(const uint32_t, const uint32_t)> remove_func = [&go, &test_list, &lock](const uint32_t elems, const uint32_t val)
	{
		const uint32_t iter_watchdog = 500000;
		while(!go)
		{
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		}

		uint32_t removed_elems = 0;
		uint32_t iter_countdown = iter_watchdog;
		while(removed_elems < elems)
		{
			{
				scoped_spinlock l(lock);
				if(test_list.size() > 0)
				{
					test_list.pop_front();
					++removed_elems;
					iter_countdown = iter_watchdog;
				}
				else
				{
					// If we've spun for a while without doing work,
					// something bad happened.
					--iter_countdown;
					ASSERT_GT(iter_countdown, 0);
					if(iter_countdown == 0)
					{
						return;
					}
				}
			}
		}
	};

	std::list<std::thread*> thread_list;

	// Spin up threads
	for(uint32_t t = 0; t < num_threads; ++t)
	{
		auto tp = new std::thread((t % 2 == 0) ? add_func : remove_func, elems_per_thread, t);
		thread_list.push_back(tp);
	}

	go = true;

	// Wait for threads to finish
	while(thread_list.size() > 0)
	{
		auto tp = thread_list.front();
		tp->join();
		delete tp;
		thread_list.pop_front();
	}

	// Validate results
	ASSERT_EQ(test_list.size(), 0);
}
