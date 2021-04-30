#include "thread_pool.h"

#include <thread>
#include <stack>
#include <cstdint>
#include <spinlock.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <chrono>
#include <common_logger.h>

COMMON_LOGGER();

thread_pool::thread_pool(uint16_t max_threads):
    m_run(true),
    m_max_threads(max_threads),
    m_id_seed(1)
{
}

thread_pool::~thread_pool()
{
	m_run = false;
	m_cv.notify_all();

	for (auto& t : m_threads)
	{
		t.join();
	}
}

void thread_pool::run_loop(thread_pool &tp)
{
	tp_work_item* item = nullptr;

	while (tp.m_run)
	{
		// Get an item from the work queue
		{
			scoped_spinlock s(tp.m_pool_lock);
			if (!tp.m_queue.empty())
			{
				item = nullptr;
				// Walk through the list until we find an item that can run
				for (auto it = tp.m_queue.begin(); it != tp.m_queue.end(); ++it)
				{
					// If the work item has a client ID, only remove the item from the
					// list if there's not another item from the same client already running.
					if (!(*it)->has_client_id() ||
					    tp.m_current_clients.find((*it)->get_client_id()) == tp.m_current_clients.end())
					{
						item = *it;
						tp.m_queue.erase(it);
						break;
					}
				}

				if (item != nullptr)
				{
					if (item->has_client_id())
					{
						// Need to modify this while still holding the spinlock
						tp.m_current_clients.insert(item->get_client_id());
					}
				}
			}
			else
			{
				item = nullptr;
			}
		}

		// Process the item (if we got one)
		if (item)
		{
			LOG_DEBUG("Processing thread pool item");
			item->handle_work();
			{
				scoped_spinlock s(tp.m_pool_lock);
				if (item->has_client_id())
				{
					tp.m_current_clients.erase(item->get_client_id());
				}
			}
			delete item;
		}
		else
		{
			// Sleep
			std::unique_lock<std::mutex> l(tp.m_wait_lock);
			tp.m_cv.wait_for(l, std::chrono::seconds(1));
		}
	}
}

void thread_pool::submit_work(tp_work_item* work_item)
{
	scoped_spinlock s(m_pool_lock);
	if (m_threads.size() < m_max_threads)
	{
		LOG_DEBUG("Spinning up a new thread pool thread");
		// Time to spin up a new thread
		m_threads.emplace_back(run_loop, std::ref(*this));
	}
	LOG_DEBUG("Submitting new work item to thread pool");
	m_queue.push_back(work_item);
	m_cv.notify_one();
}

tp_work_item::client_id thread_pool::build_new_client_id() const
{
	return m_id_seed++;
}
