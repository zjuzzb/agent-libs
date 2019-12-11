#include <atomic>
#include <gtest.h>
#include <functional>
#include <random>
#include <time.h>
#include <Poco/Runnable.h>
#include <Poco/ThreadPool.h>
#include "Poco/Thread.h"
#include "thread_safe_container/guarded_cache.h"
#include "thread_safe_container/guarded_cache.hpp"

using Poco::ThreadPool;

namespace
{

std::string random_string( size_t length )
{
	// Keeping this as a array so the size is determined at compile-time
	static const char CHARSET[] = "0123456789"
				      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				      "abcdefghijklmnopqrstuvwxyz";
	auto randchar = []() -> char
	{
		const size_t max_index = (sizeof(CHARSET) - 1);
		return CHARSET[rand() % max_index];
	};

	std::string str(length,0);
	std::generate_n( str.begin(), length, randchar );
	return str;
}

/**
 * This struct has stuff in it.
 */
struct stuff
{
	stuff() :
		a(0),
		b(0),
		c(0)
	{}

	stuff(int a_val, int b_val, int c_val) :
	   a(a_val),
	   b(b_val),
	   c(c_val)
	{ }

	int a;
	int b;
	int c;

	// Default move
	stuff(stuff&& rhs) = default;

	// Allow copies
	stuff(stuff& rhs) = default;
	stuff(const stuff& rhs) = default;
	stuff& operator=(stuff& rhs) = default;
	stuff& operator=(const stuff& rhs) = default;

	bool operator==(const stuff& rhs) const
	{
		return a == rhs.a && b == rhs.b && c == rhs.c;
	}

};
using stuff_map = thread_safe_container::guarded_cache<std::string, stuff>;

/**
 * The change_stuff_runnable add/deletes/modifies the map but does it in a
 * way that it is in a known state when it unlocks.
 */
class change_stuff_runnable : public Poco::Runnable
{
public:
	change_stuff_runnable(stuff_map& stuff) :
	   m_stuff(stuff),
	   m_abort(false)
	{

	}

	void abort()
	{
		m_abort = true;
	}

	virtual void run() override
	{

		while (!m_abort)
		{
			std::string key = "my-key-" + random_string(10);
			m_stuff.insert(key, stuff());

			m_stuff.visit([](stuff_map::element_pair& value) {
				value.second.a++;
				value.second.b++;
				value.second.c++;
			});

			{
				auto rw_handle = m_stuff.read_write_handle(key);

				rw_handle->a++;
				rw_handle->b++;
				rw_handle->c++;
			}


			{
				auto r_handle = m_stuff.read_handle(key);
				// We always leave it in a state where
				// A == B == C
				ASSERT_EQ(r_handle->a, r_handle->b);
				ASSERT_EQ(r_handle->a, r_handle->c);
			}

			m_stuff.visit([](const stuff_map::element_pair& value) {
				// We always leave it in a state where
				// A == B == C
				ASSERT_EQ(value.second.a, value.second.b);
				ASSERT_EQ(value.second.a, value.second.c);
			});

			m_stuff.erase(key);
		}
	}

private:

	stuff_map& m_stuff;
	std::atomic<bool> m_abort;
};

} // anonymous namespace


TEST(guarded_cache_test, threading)
{
	stuff_map some_stuff;
	some_stuff.insert(std::string("abcd"), stuff());
	some_stuff.insert(std::string("efgh"), stuff());
	stuff my_stuff;
	some_stuff.emplace(std::string("ijkl"), std::move(my_stuff));

	change_stuff_runnable change_stuff_1(some_stuff);
	change_stuff_runnable change_stuff_2(some_stuff);
	change_stuff_runnable change_stuff_3(some_stuff);
	change_stuff_runnable change_stuff_4(some_stuff);
	change_stuff_runnable change_stuff_5(some_stuff);

	ThreadPool::defaultPool().start(change_stuff_1, "change_stuff_1");
	ThreadPool::defaultPool().start(change_stuff_2, "change_stuff_2");
	ThreadPool::defaultPool().start(change_stuff_3, "change_stuff_3");
	ThreadPool::defaultPool().start(change_stuff_4, "change_stuff_4");
	ThreadPool::defaultPool().start(change_stuff_5, "change_stuff_5");

	Poco::Thread::sleep(2000 /*ms*/);

	change_stuff_1.abort();
	change_stuff_2.abort();
	change_stuff_3.abort();
	change_stuff_4.abort();
	change_stuff_5.abort();

	// Join to ensure we wait for everything to stop
	ThreadPool::defaultPool().joinAll();
}

// Ensure basic functionality of the class, namely that you can read what you
// write.
TEST(guarded_cache_test, insert_read_erase)
{
	stuff_map some_stuff;

	stuff my_stuff(1, 2, 3);
	std::string key("key");

	some_stuff.insert(key, my_stuff);
	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_EQ(my_stuff, *handle);
	}

	const int WRITE_VALUE = 99;
	{
		auto handle = some_stuff.read_write_handle(key);
		ASSERT_EQ(my_stuff, *handle);
		handle->a = WRITE_VALUE;
	}
	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_EQ(handle->a, WRITE_VALUE);
	}

	some_stuff.erase(key);
	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_TRUE(!handle.valid());
	}
}

TEST(guarded_cache_test, insert_same_key_twice)
{
	stuff_map some_stuff;
	std::string key("key");
	stuff my_stuff(1, 2, 3);

	bool result = some_stuff.insert(key, my_stuff);
	ASSERT_TRUE(result);
	result = some_stuff.insert(key, stuff());
	ASSERT_FALSE(result);

	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_EQ(my_stuff, *handle);
	}
}

TEST(guarded_cache_test, emplace_same_key_twice)
{
	stuff_map some_stuff;
	std::string key("key");
	stuff my_stuff(1, 2, 3);

	bool result = some_stuff.emplace(std::string(key), std::move(my_stuff));
	ASSERT_TRUE(result);
	result = some_stuff.emplace(std::string(key), stuff());
	ASSERT_FALSE(result);

	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_EQ(my_stuff, *handle);
	}
}

// Ensure that we can make a struct where copies are not allowed and use it
// inside this map (with shared). If this compiles then we are good.
TEST(guarded_cache_test, basic_with_no_copy_struct)
{
	struct no_copy_stuff
	{
		using ptr_t = std::shared_ptr<no_copy_stuff>;

		no_copy_stuff() :
		   a(0),
		   b(0),
		   c(0)
		{ }

		int a;
		int b;
		int c;

		// Don't allow copies
		no_copy_stuff(no_copy_stuff& rhs) = delete;
		no_copy_stuff(const no_copy_stuff& rhs) = delete;
		no_copy_stuff& operator=(no_copy_stuff& rhs) = delete;
		no_copy_stuff& operator=(const no_copy_stuff& rhs) = delete;
	};
	using no_copy_stuff_map = thread_safe_container::guarded_cache<std::string, no_copy_stuff::ptr_t>;

	no_copy_stuff_map some_stuff;
	std::string key = "key";
	some_stuff.insert(key, std::make_shared<no_copy_stuff>());

	const int WRITE_VALUE = 99;
	{
		auto handle = some_stuff.read_write_handle(key);
		(*handle)->a = WRITE_VALUE;
	}

	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_EQ((*handle)->a, WRITE_VALUE);
	}

	some_stuff.erase(key);
	{
		auto handle = some_stuff.read_handle(key);
		ASSERT_TRUE(!handle.valid());
	}
}




