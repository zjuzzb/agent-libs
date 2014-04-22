#pragma once

#include "main.h"

#include "logger.h"

template<class T>
class blocking_queue
{
public:
	blocking_queue(uint32_t max_size);

	bool put(T item);
	bool get(T* item, uint64_t timeout_ms);
	bool is_full();

private:
	const uint32_t m_max_size;
	queue<T> m_queue;
	Mutex m_mutex;
	Semaphore m_semaphore;
};

template<class T>
blocking_queue<T>::blocking_queue(uint32_t max_size) :
	m_max_size(max_size),
	m_semaphore(0, max_size)
{
}

template<class T>
bool blocking_queue<T>::put(T item)
{
	{
		Mutex::ScopedLock lock(m_mutex);

		if(m_queue.size() == m_max_size)
		{
			return false;
		}

		m_queue.push(item);
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
		ASSERT(!m_queue.empty());
		T p = m_queue.front();
		m_queue.pop();
		*item = p;
	}

	return res;
}

template<class T>
bool blocking_queue<T>::is_full()
{
	Mutex::ScopedLock lock(m_mutex);

	return m_queue.size() == m_max_size;
}
