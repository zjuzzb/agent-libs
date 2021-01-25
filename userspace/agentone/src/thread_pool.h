#pragma once

#include <thread>
#include <queue>
#include <vector>
#include <spinlock.h>
#include <cstdint>
#include <atomic>
#include <condition_variable>
#include <mutex>

class tp_work_item
{
public:
	virtual ~tp_work_item() {}

	virtual void handle_work() = 0;
};

/**
 * Manages a set of worker threads who consume work items from an input queue.
 *
 * How to use:
 * 1. Create a class that inherits from tp_work_item and implements handle_work.
 * 2. Create an instance of this class when you need work to be handled by the pool.
 * 3. Provide the instance to submit_work. The thread pool will handle it.
 */
class thread_pool
{
public:
	thread_pool(uint16_t max_threads);
	~thread_pool();

	/**
	 * Handle the given work item on a thread pool thread.
	 */
	void submit_work(tp_work_item* work_item);

private:
	static void run_loop(thread_pool& tp);

private:
	/// Threads managed by the thread pool
	std::vector<std::thread> m_threads;

	/// Should the pool's threads run?
	std::atomic<bool> m_run;

	/// The maximum number of threads to create
	uint16_t m_max_threads;

	/// Lock for both m_queue and m_threads
	spinlock m_pool_lock;

	/// The work queue to be serviced by the thread pool's threads
	std::queue<tp_work_item*> m_queue;

	/// Notifies the thread pool's threads that there's new work
	std::condition_variable m_cv;

	/// Lock for m_cv
	std::mutex m_wait_lock;
};

