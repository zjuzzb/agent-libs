#include <atomic>
#include <gtest.h>
#include <functional>
#include <time.h>
#include <Poco/Runnable.h>
#include "Poco/Thread.h"
#include "blocking_queue.h"

namespace
{

const int LOOPS = 1000;
blocking_queue<int> s_queue(LOOPS);
std::atomic<bool> s_abort(false);


// Push into s_queue
class push_runnable : public Poco::Runnable
{
private:
	int m_my_int = 22;

	virtual void run() override
	{
		s_queue.clear();

		while(!s_abort)
		{
			if(s_queue.put(m_my_int))
			{
				m_my_int++;
			}

			Poco::Thread::sleep(1);
		}
	}
};

// Pop from s_queue
class wait_and_pop_runnable : public Poco::Runnable
{
private:

	int m_previous = 0;

	virtual void run() override
	{
		int value = 0;
		while(value < LOOPS)
		{
			(void) s_queue.get(&value, 1000 /*ms*/);

			test_incrementing(value);
		}

		s_abort = true;
	}


	void test_incrementing(int value)
	{
		if(m_previous)
		{
			ASSERT_EQ(value, m_previous + 1);
		}

		m_previous = value;
	}
};


} // anonymous namespace


TEST(blocking_queue_test, basic)
{
	s_abort = false;
	push_runnable push_it;
	wait_and_pop_runnable pop_it;

	ThreadPool::defaultPool().start(push_it, "push");
	ThreadPool::defaultPool().start(pop_it, "wait and pop");

	ThreadPool::defaultPool().joinAll();
}




