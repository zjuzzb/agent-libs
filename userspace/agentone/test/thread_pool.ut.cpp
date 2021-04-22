#include "thread_pool.h"

#include <gtest.h>

#include <atomic>
#include <cstdint>
#include <list>
#include <unistd.h>

class boolean_work_item : public tp_work_item
{
public:
	boolean_work_item(bool* toggle) : m_toggle(toggle) {}

	virtual void handle_work() override
	{
		if (*m_toggle)
		{
			*m_toggle = false;
		}
		else
		{
			*m_toggle = true;
		}
	}

private:
	bool* m_toggle;
};

////
class counting_work_item : public tp_work_item
{
public:
	counting_work_item(uint32_t* counter) : m_counter(counter) {}

	virtual void handle_work() override
	{
		++(*m_counter);
	}

private:
	uint32_t* m_counter;
};

////
class atomic_counting_work_item : public tp_work_item
{
public:
	atomic_counting_work_item(std::atomic<uint32_t>* counter) : m_counter(counter) {}

	virtual void handle_work() override
	{
		++(*m_counter);
	}

private:
	std::atomic<uint32_t>* m_counter;
};

////
class signal_work_item : public tp_work_item
{
public:
	signal_work_item(uint64_t client_id,
	                 uint32_t wi_id,
	                 std::atomic<bool>* signal,
	                 std::atomic<bool>* token) :
	    tp_work_item(client_id),
	    m_id(wi_id),
	    m_signal(signal),
	    m_token(token)
	{
		*m_signal = false;
		*m_token = false;
	}

	uint32_t get_id() const { return m_id; }

	virtual void handle_work() override
	{
		*m_token = false;
		while (!(*m_signal))
		{
			usleep(100);
		}
		*m_token = true;
	}

private:
	uint32_t m_id;
	std::atomic<bool>* m_signal;
	std::atomic<bool>* m_token;
};

TEST(thread_pool, single_thread_single_work_item)
{
	thread_pool tp(1);
	bool flag = false;
	auto* bwi = new boolean_work_item(&flag);

	// The thread pool takes ownership of the work item pointer
	tp.submit_work(bwi);

	for (uint32_t loops = 0; !flag && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_TRUE(flag);
}

TEST(thread_pool, single_thread_signal_work_item)
{
	thread_pool tp(1);
	std::atomic<bool> s, t;
	auto* swi = new signal_work_item(0, 0, &s, &t);

	// The thread pool takes ownership of the work item pointer
	tp.submit_work(swi);

	for (uint32_t loops = 0; loops < 100; ++loops)
	{
		usleep(1000);
	}

	ASSERT_FALSE(t);
	ASSERT_FALSE(s);

	s = true;

	for (uint32_t loops = 0; !t && loops < 1000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_TRUE(s);
	ASSERT_TRUE(t);
}

TEST(thread_pool, single_thread_multiple_work_item_types)
{
	thread_pool tp(1);
	bool flag = false;
	uint32_t counter = 0;
	auto* bwi = new boolean_work_item(&flag);
	auto* cwi = new counting_work_item(&counter);

	// The thread pool takes ownership of the work item pointer
	tp.submit_work(bwi);
	tp.submit_work(cwi);

	for (uint32_t loops = 0; counter == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_TRUE(flag);
	ASSERT_EQ(1, counter);
}

TEST(thread_pool, single_thread_multiple_work_items)
{
	const uint32_t num_items = 100;
	thread_pool tp(1);
	uint32_t counter = 0;
	std::list<counting_work_item*> cwi_list;

	for (uint32_t i = 0; i < num_items; ++i)
	{
		cwi_list.push_back(new counting_work_item(&counter));
	}

	// Don't have to worry about serializing counter because
	// only one thread in the pool
	for (auto& li : cwi_list)
	{
		// The thread pool takes ownership of the work item pointer
		tp.submit_work(li);
	}

	for (uint32_t loops = 0; counter < num_items && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(num_items, counter);
}

TEST(thread_pool, multi_thread_single_work_item)
{
	thread_pool tp(2);
	bool flag = false;
	auto* bwi = new boolean_work_item(&flag);

	// The thread pool takes ownership of the work item pointer
	tp.submit_work(bwi);

	for (uint32_t loops = 0; !flag && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_TRUE(flag);
}

TEST(thread_pool, multi_thread_multiple_work_items)
{
	const uint32_t num_items = 100;
	thread_pool tp(2);
	std::atomic<uint32_t> counter(0);
	std::list<atomic_counting_work_item*> cwi_list;

	for (uint32_t i = 0; i < num_items; ++i)
	{
		cwi_list.push_back(new atomic_counting_work_item(&counter));
	}

	for (auto& li : cwi_list)
	{
		// The thread pool takes ownership of the work item pointer
		tp.submit_work(li);
	}

	for (uint32_t loops = 0; counter < num_items && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(num_items, counter);
}

TEST(thread_pool, multi_thread_multi_client)
{
	const uint32_t num_client_items = 10;
	const uint32_t num_basic_items = 50;
	const uint64_t client_id = 2;
	const uint64_t other_client_id = 1;
	thread_pool tp(2);
	std::atomic<uint32_t> counter(0);
	std::atomic<bool> tokens[num_client_items];
	std::atomic<bool> sigs[num_client_items];
	std::list<atomic_counting_work_item*> cwi_list;
	std::list<signal_work_item*> sig_list;

	// The other blocking SWI
	std::atomic<bool> t, s;
	signal_work_item* swi = new signal_work_item(other_client_id, 999, &s, &t);

	for (uint32_t i = 0; i < num_basic_items; ++i)
	{
		cwi_list.push_back(new atomic_counting_work_item(&counter));
	}

	for (uint32_t i = 0; i < num_client_items; ++i)
	{
		sig_list.push_back(new signal_work_item(client_id, i, &sigs[i], &tokens[i]));
	}

	// Seed the thread pool input queue
	tp.submit_work(swi);
	swi = sig_list.front();
	tp.submit_work(swi);
	sig_list.pop_front();
	while (!sig_list.empty())
	{
		for (uint32_t i = 0; i < num_client_items && !cwi_list.empty(); ++i)
		{
			auto* cwi = cwi_list.front();
			tp.submit_work(cwi);
			cwi_list.pop_front();
		}
		swi = sig_list.front();
		tp.submit_work(swi);
		sig_list.pop_front();
	}

	// At this point, the thread pool should be completely stalled, with a
	// signal work item on each of its two threads.
	ASSERT_FALSE(sigs[0]);
	ASSERT_FALSE(tokens[0]);
	ASSERT_FALSE(t);
	ASSERT_FALSE(s);
	ASSERT_EQ(0, counter);

	// If we signal the SWI with client_id 2, that should let SOME of the
	// CWIs through.
	sigs[0] = true;

	for (uint32_t loops = 0; counter < num_client_items && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(num_client_items, counter);
	ASSERT_TRUE(sigs[0]);
	ASSERT_TRUE(tokens[0]);
	ASSERT_FALSE(t);
	ASSERT_FALSE(sigs[1]);
	ASSERT_FALSE(tokens[1]);

	// Now if we signal the SWI with client_id 1, the rest of the CWIs should
	// finish without ANY of the SWIs being enqueued
	s = true;

	for (uint32_t loops = 0; counter < num_basic_items && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(num_basic_items, counter);
	ASSERT_TRUE(t);
	ASSERT_FALSE(sigs[1]);
	ASSERT_FALSE(tokens[1]);

	// Now we're going to signal all of the SWIs except the one currently running
	// on the thread pool (index 1). This will ensure that even though we have a
	// free thread, the SWIs are being serialized.

	for (uint32_t i = 2; i < num_client_items; ++i)
	{
		sigs[i] = true;
	}
	for (uint32_t i = 1; i < num_client_items; ++i)
	{
		ASSERT_FALSE(tokens[i]);
	}

	// Now once we signal the SWI at index 1, all SWIs should be processed one by
	// one through the thread pool
	sigs[1] = true;
	for (uint32_t loops = 0; !tokens[num_client_items - 1] && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	for (uint32_t i = 0; i < num_client_items; ++i)
	{
		ASSERT_TRUE(tokens[i]);
	}
}
