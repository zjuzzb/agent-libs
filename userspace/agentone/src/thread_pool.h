#pragma once

#include <thread>
#include <list>
#include <vector>
#include <spinlock.h>
#include <cstdint>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <unordered_set>

class tp_work_item
{
public:
	using client_id = uint64_t;
	const client_id null_id = 0;

	tp_work_item() : m_client_id(null_id) {}
	tp_work_item(client_id id) : m_client_id(id) {}
	virtual ~tp_work_item() {}

	virtual void handle_work() = 0;

	client_id get_client_id() const { return m_client_id; }
	bool has_client_id() const { return m_client_id != null_id; }

private:
	client_id m_client_id;
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

	tp_work_item::client_id build_new_client_id() const;

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
	/// Note: Not actually a queue structure, as client serialization
	///       can lead to non-FIFO processing.
	std::list<tp_work_item*> m_queue;

	/// Notifies the thread pool's threads that there's new work
	std::condition_variable m_cv;

	/// Lock for m_cv
	std::mutex m_wait_lock;

	/// Set of currently running client IDs
	std::unordered_set<tp_work_item::client_id> m_current_clients;

	/// Seed for assigning client IDs
	mutable uint64_t m_id_seed;
};

