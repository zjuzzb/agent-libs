#pragma once

#include "main.h"

class blocking_queue
{
public:

	class item
	{
	public:

		item(char* buf, uint32_t len)
		{
			m_buf = new char[len];
			memcpy(m_buf, buf, len);
			m_len = len;
		}

		~item()
		{
			if(m_buf)
			{
				delete[] m_buf;
				m_buf = NULL;
			}
		}

		char* m_buf;
		uint32_t m_len;
	};

	blocking_queue() :
		m_semaphore(0, BLOCKING_SIZE)
	{
	}

	void put(item* item)
	{
		{
			Mutex::ScopedLock lock(m_mutex);
			m_queue.push(item);
		}

		m_semaphore.set();
	}

	item* get()
	{
		m_semaphore.wait();

		{
			Mutex::ScopedLock lock(m_mutex);
			ASSERT(!m_queue.empty());
			item* item = m_queue.front();
			m_queue.pop();
			return item;
		}
	}

private:
	static const uint32_t BLOCKING_SIZE = 32;

	queue<item*> m_queue;
	Mutex m_mutex;
	Semaphore m_semaphore;
};
