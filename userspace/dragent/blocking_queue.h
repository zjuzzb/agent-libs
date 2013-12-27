#pragma once

#include "main.h"

#include "logger.h"

template<class T>
class blocking_queue
{
public:
	blocking_queue();

	bool put(T item);
	T get();

private:
	static const uint32_t BLOCKING_SIZE = 32;

	queue<T> m_queue;
	Mutex m_mutex;
	Semaphore m_semaphore;
};

template<class T>
blocking_queue<T>::blocking_queue() :
	m_semaphore(0, BLOCKING_SIZE)
{
}

template<class T>
bool blocking_queue<T>::put(T item)
{
	{
		Mutex::ScopedLock lock(m_mutex);

		if(m_queue.size() == BLOCKING_SIZE)
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
