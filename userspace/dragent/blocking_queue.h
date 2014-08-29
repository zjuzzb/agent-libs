#pragma once

#include "main.h"

#include "logger.h"

template<class T>
class blocking_queue
{
public:
	enum item_priority
	{
		BQ_PRIORITY_HIGH = 0,
		BQ_PRIORITY_MEDIUM = 1,
		BQ_PRIORITY_LOW = 2,
		BQ_PRIORITY_SIZE = 3
	};

	blocking_queue(uint32_t max_size);

	bool put(T item, item_priority priority = BQ_PRIORITY_MEDIUM);
	bool get(T* item, uint64_t timeout_ms);
	bool is_full(item_priority priority);
	size_t size(item_priority priority);
	size_t size();
	void clear();

private:
	const uint32_t m_max_size;
	queue<T> m_queues[BQ_PRIORITY_SIZE];
	Mutex m_mutex;
	Semaphore m_semaphore;
};

template<class T>
blocking_queue<T>::blocking_queue(uint32_t max_size) :
	m_max_size(max_size),
	m_semaphore(0, max_size * BQ_PRIORITY_SIZE)
{
}

template<class T>
bool blocking_queue<T>::put(T item, item_priority priority)
{
	ASSERT(priority < BQ_PRIORITY_SIZE);

	{
		Mutex::ScopedLock lock(m_mutex);

		if(m_queues[priority].size() == m_max_size)
		{
			return false;
		}

		m_queues[priority].push(item);
	}

	m_semaphore.set();
	return true;
}

template<class T>
bool blocking_queue<T>::get(T* item, uint64_t timeout_ms)
{
	bool res = m_semaphore.tryWait(timeout_ms);

	if(res)
	{
		Mutex::ScopedLock lock(m_mutex);

		for(uint32_t j = 0; j < BQ_PRIORITY_SIZE; ++j)
		{
			if(!m_queues[j].empty())
			{
				T p = m_queues[j].front();
				m_queues[j].pop();
				if(item)
				{
					*item = p;
				}
				break;
			}
		}
	}

	return res;
}

template<class T>
bool blocking_queue<T>::is_full(item_priority priority)
{
	ASSERT(priority < BQ_PRIORITY_SIZE);
	Mutex::ScopedLock lock(m_mutex);

	return m_queues[priority].size() == m_max_size;
}

template<class T>
size_t blocking_queue<T>::size(item_priority priority)
{
	ASSERT(priority < BQ_PRIORITY_SIZE);
	Mutex::ScopedLock lock(m_mutex);

	return m_queues[priority].size();
}

template<class T>
size_t blocking_queue<T>::size()
{
	size_t s = 0;

	for(uint32_t j = 0; j < BQ_PRIORITY_SIZE; ++j)
	{
		s += size((item_priority) j);
	}

	return s;
}

template<class T>
void blocking_queue<T>::clear()
{
	while(get(NULL, 0));
}
