/**
 * @file
 *
 * Executable unit tests for async_key_value_source.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "async_key_value_source.h"

#include <string>
#include <gtest.h>

using namespace sysdig;

namespace
{

/**
 * Intermediate realization of async_key_value_source that can return pre-canned
 * results.
 */
class precanned_metadata_source : public async_key_value_source<std::string, std::string> 
{
public:
	const static uint64_t FOREVER_MS;

	precanned_metadata_source(const uint64_t max_wait_ms,
	                          const uint64_t ttl_ms = FOREVER_MS)
		: async_key_value_source(max_wait_ms, ttl_ms),
		m_responses()
	{ }

	void set_response(const std::string& key, const std::string& response)
	{
		m_responses[key] = response;
	}

	std::string get_response(const std::string& key)
	{
		return m_responses[key];
	}

private:
	std::map<std::string, std::string> m_responses;
};
const uint64_t precanned_metadata_source::FOREVER_MS = static_cast<uint64_t>(~0L);

/**
 * Realization of async_key_value_source that returns results without delay.
 */
class immediate_metadata_source : public precanned_metadata_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	immediate_metadata_source(const uint64_t max_wait_ms=MAX_WAIT_TIME_MS):
		precanned_metadata_source(max_wait_ms)
	{ }

protected:
	virtual void run_impl() override
	{
		std::string key;

		while(dequeue_next_key(key))
		{
			store_value(key, get_response(key));
		}
	}
};
const uint64_t immediate_metadata_source::MAX_WAIT_TIME_MS = 5000;

/**
 * Realization of async_key_value_source that returns results with some
 * specified delay.
 */
class delayed_metadata_source : public precanned_metadata_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	delayed_metadata_source(const uint64_t delay_ms,
	                        const uint64_t ttl_ms = FOREVER_MS):
		precanned_metadata_source(MAX_WAIT_TIME_MS, ttl_ms),
		m_delay_ms(delay_ms),
		m_response_available(false)
	{ }

	bool is_response_available() const
	{
		return m_response_available;
	}

protected:
	virtual void run_impl() override
	{
		std::string key;

		m_response_available = false;

		while(dequeue_next_key(key))
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(m_delay_ms));
			store_value(key, get_response(key));
			m_response_available = true;
		}
	}

private:
	uint64_t m_delay_ms;
	bool m_response_available;
};
const uint64_t delayed_metadata_source::MAX_WAIT_TIME_MS = 0;

}

/**
 * Ensure that a concrete async_key_value_source is in the expected initial
 * state after construction.
 */
TEST(async_key_value_source_test, construction)
{
	immediate_metadata_source source;

	ASSERT_EQ(immediate_metadata_source::MAX_WAIT_TIME_MS,
	          source.get_max_wait());
	ASSERT_EQ(precanned_metadata_source::FOREVER_MS, source.get_ttl());
	ASSERT_FALSE(source.is_running());
}

/**
 * Ensure that if a concrete async_key_value_source returns the metadata before
 * the timeout, that the lookup() method returns true, and that it returns
 * the metadata in the output parameter.
 */
TEST(async_key_value_source_test, lookup_key_immediate_return)
{
	const std::string key = "foo";
	const std::string metadata = "bar";
	std::string response = "response-not-set";

	immediate_metadata_source source;

	// Seed the precanned response
	source.set_response(key, metadata);

	ASSERT_TRUE(source.lookup(key, response));
	ASSERT_EQ(metadata, response);
	ASSERT_TRUE(source.is_running());
}

/**
 * Ensure that get_complete_results returns all complete results
 */
TEST(async_key_value_source_test, get_complete_results)
{
	const std::string key1 = "foo1";
	const std::string key2 = "foo2";
	const std::string metadata = "bar";
	std::string response1 = "response1-not-set";
	std::string response2 = "response2-not-set";

	delayed_metadata_source source(500);

	// Seed the precanned response
	source.set_response(key1, metadata);
	source.set_response(key2, metadata);

	EXPECT_FALSE(source.lookup(key1, response1));
	EXPECT_FALSE(source.lookup(key2, response2));
	EXPECT_EQ("response1-not-set", response1);
	EXPECT_EQ("response2-not-set", response2);

	usleep(1100000);
	EXPECT_TRUE(source.is_running());
	auto completed = source.get_complete_results();

	EXPECT_EQ(2, completed.size());
	EXPECT_EQ(metadata, completed[key1]);
	EXPECT_EQ(metadata, completed[key2]);
}

/**
 * Ensure that get_complete_results returns all complete results
 * but does *not* return results that have not yet been computed
 */
TEST(async_key_value_source_test, get_complete_results_incomplete)
{
	const std::string key1 = "foo1";
	const std::string key2 = "foo2";
	const std::string metadata = "bar";
	std::string response1 = "response1-not-set";
	std::string response2 = "response2-not-set";

	delayed_metadata_source source(500);

	// Seed the precanned response
	source.set_response(key1, metadata);
	source.set_response(key2, metadata);

	EXPECT_FALSE(source.lookup(key1, response1));
	EXPECT_FALSE(source.lookup(key2, response2));
	EXPECT_EQ("response1-not-set", response1);
	EXPECT_EQ("response2-not-set", response2);

	usleep(600000);
	EXPECT_TRUE(source.is_running());
	auto completed = source.get_complete_results();

	EXPECT_EQ(1, completed.size());
	EXPECT_EQ(metadata, completed[key1]);
}

/**
 * Ensure that lookup_delayed() does not return the value immediately
 * but only after the specified time
 */
TEST(async_key_value_source_test, lookup_delayed)
{
	const std::string key = "foo_delayed";
	const std::string metadata = "bar";
	std::string response = "response-not-set";

	immediate_metadata_source source(0);

	// Seed the precanned response
	source.set_response(key, metadata);

	// the delayed lookup cannot return a value right away
	EXPECT_FALSE(source.lookup_delayed(key, response, std::chrono::milliseconds(500)));
	EXPECT_EQ("response-not-set", response);

	// after 300 ms, the response should not yet be ready
	usleep(300000);
	EXPECT_TRUE(source.is_running());
	EXPECT_EQ("response-not-set", response);

	// add 100 ms just in case -- after 600 ms we should have the response
	usleep(300000);
	EXPECT_TRUE(source.is_running());
	EXPECT_TRUE(source.lookup(key, response));
	EXPECT_EQ(metadata, response);
}

/**
 * Ensure that if a concrete async_key_value_source cannot return the result
 * before the timeout, and if the client did not provide a callback, that
 * calling lookup() after the result it available returns the value.
 */
TEST(async_key_value_source_test, lookup_key_delayed_return_second_call)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metadata = "myvalue";

	delayed_metadata_source source(DELAY_MS);

	std::string response = "response-not-set";
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metadata);

	response_found = source.lookup(key, response);

	ASSERT_FALSE(response_found);

	// Since we didn't supply a callback, a subsequent call to lookup
	// after the metadata collection is complete will return the previously
	// collected metadata.  We know it should delay DELAY_MS, so wait that
	// long, but expect some scheduling overhead.  If we have to wait more
	// than 5 seconds, something went wrong.
	std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_MS));
	const int FIVE_SECS_IN_MS = 5 * 1000;
	for(int i = 0; !source.is_response_available() && i < FIVE_SECS_IN_MS; ++i)
	{
		// Avoid tight busy loop
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// Response should now be available
	response_found = source.lookup(key, response);

	ASSERT_TRUE(response_found);
	ASSERT_EQ(metadata, response);
}

/**
 * Ensure that if a concrete async_key_value_source cannot return the result
 * before the timeout, and if the client did provide a callback, that the
 * callback is invoked with the metadata once they're avaialble.
 */
TEST(async_key_value_source_test, look_key_delayed_async_callback)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metadata = "myvalue";

	delayed_metadata_source source(DELAY_MS);

	std::string sync_response = "sync-response-not-set";
	std::string async_response = "async-response-not-set";
	bool async_response_received = false;
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metadata);

	response_found = source.lookup(key,
	                               sync_response,
	                               [&async_response, &async_response_received]
	                                   (const std::string& key,
	                                    const std::string& value)
	{
		async_response = value;
		async_response_received = true;
	});

	ASSERT_FALSE(response_found);

	// Since we didn't supply a callback, a subsequent call to lookup
	// after the metadata collection is complete will return the previously
	// collected metadata.  We know it should delay DELAY_MS, so wait that
	// long, but expect some scheduling overhead.  If we have to wait more
	// than 5 seconds, something went wrong.
	std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_MS));
	const int FIVE_SECS_IN_MS = 5 * 1000;
	for(int i = 0; !async_response_received && i < FIVE_SECS_IN_MS; ++i)
	{
		// Avoid tight busy loop
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	ASSERT_EQ(metadata, async_response);
}

/**
 * Ensure that "old" results are pruned
 */
TEST(async_key_value_source_test, prune_old_metadata)
{
	const uint64_t DELAY_MS = 0;
	const uint64_t TTL_MS = 20;

	const std::string key1 = "mykey1";
	const std::string metadata1 = "myvalue1";

	const std::string key2 = "mykey2";
	const std::string metadata2 = "myvalue2";

	delayed_metadata_source source(DELAY_MS, TTL_MS);
	std::string response = "response-not-set";

	// Seed the precanned response
	source.set_response(key1, metadata1);
	source.set_response(key2, metadata2);

	// Since DELAY_MS is 0, then lookup should return false immediately,
	// and should almost immediately add the result to the cache
	ASSERT_FALSE(source.lookup(key1, response));

	// Wait long enough for the old entry to require pruning
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * TTL_MS));

	// Request the other key.  This should wake up the thread and actually
	// preform the pruning.
	ASSERT_FALSE(source.lookup(key2, response));

	// Wait long enough for the async thread to get woken up and to
	// prune the old entry
	std::this_thread::sleep_for(std::chrono::milliseconds(TTL_MS));

	// Since the first key should have been pruned, a second call to
	// fetch the first key should also return false.
	ASSERT_FALSE(source.lookup(key1, response));
}
