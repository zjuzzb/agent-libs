#pragma once

#include "main.h"

#include "logger.h"

template<class T>
class blocking_queue
{
public:
	blocking_queue(uint32_t max_size);

	bool put(T item);
	T get();

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
T blocking_queue<T>::get()
{
	m_semaphore.wait(1000);

	{
		Mutex::ScopedLock lock(m_mutex);
		ASSERT(!m_queue.empty());
		T item = m_queue.front();
		m_queue.pop();
		return item;
	}
}

typedef string dragent_queue_item;
typedef blocking_queue<SharedPtr<dragent_queue_item>> dragent_queue;
