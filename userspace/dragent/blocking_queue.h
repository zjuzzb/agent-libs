#pragma once

#include "main.h"

template<class T>
class blocking_queue
{
public:

	blocking_queue() :
		m_semaphore(0, BLOCKING_SIZE)
	{
	}

	bool put(T item)
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

	T get()
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

private:
	static const uint32_t BLOCKING_SIZE = 32;

	queue<T> m_queue;
	Mutex m_mutex;
	Semaphore m_semaphore;
};

typedef string dragent_queue_item;
typedef blocking_queue<SharedPtr<dragent_queue_item>> dragent_queue;
