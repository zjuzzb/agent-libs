
#include <container_size_requestor.h>
#include <gtest.h>
#include <vector>
#include <common_logger.h>
#include <scoped_configuration.h>
#include <scoped_sinsp_logger_capture.h>
#include <sinsp_mock.h>

using namespace test_helpers;

namespace {

COMMON_LOGGER();

const uint64_t MS_PER_SEC = 1000;

/**
 * Test helper to keep track of which containers have been requested.
 */
class container_counter
{
public:
	/**
	 * Add a container that will be tracked
	 */
	void add(const sinsp_container_info::ptr_t& info)
	{
		m_expected.push_back(info);
	}

	/**
	 * Called by the class under test. We mark given containers as found.
	 */
	void update_container_with_size(sinsp_container_type type,
					const std::string& container_id)
	{
		for(auto& expected : m_expected)
		{
			if(expected.info->m_type != type ||
			   expected.info->m_id != container_id)
			{
				continue;
			}

			ASSERT_FALSE(expected.found);
			expected.found = true;
			return;
		}

		// Should never reach this point
		ASSERT_TRUE(false);
	}

	/**
	 * Return the number of containers that have been found.
	 */
	unsigned int found()
	{
		unsigned int to_return = 0;
		for(const auto &expected : m_expected)
		{
			if(expected.found)
			{
				++to_return;
			}
		}
		return to_return;
	}

	/**
	 * Mark all containers as not found.
	 */
	void reset()
	{
		for(auto& expected : m_expected)
		{
			expected.found = false;
		}
	}

private:
	struct expected_container
	{
		expected_container(const sinsp_container_info::ptr_t& info_val) :
		   found(false),
		   info(info_val)
		{}

		bool found;
		sinsp_container_info::ptr_t info;

	};
	std::vector<expected_container> m_expected;
};

}

TEST(container_size_requestor_test, twelve_seconds_interval)
{
	scoped_configuration config(R"(
container_size_request:
  interval_s: 12
  first_request_delay_s: 7
)");

	// We use the container_counter class to keep track of which containers
	// have been requested.
	container_counter counter;

	sinsp_mock inspector;

	auto container1 = inspector.build_container().commit();
	counter.add(container1);
	auto container2 = inspector.build_container().commit();
	counter.add(container2);
	auto container3 = inspector.build_container().id("not-alphabetical").commit();
	counter.add(container3);
	auto container4 = inspector.build_container().commit();
	counter.add(container4);

	inspector.open();

	// Create a requestor that calls into the container_counter
	container_size_requestor requestor(inspector.m_container_manager,
					   std::bind(& container_counter::update_container_with_size,
						     &counter,
						     std::placeholders::_1,
						     std::placeholders::_2));
	uint64_t uptime = 6;

	// Two seconds before cache is updated the first time
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());

	// Cache will get update here. With 4 containers every 12 seconds, we
	// should see a container get requested every 3 seconds
	ASSERT_EQ(0, requestor.cache_size());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(4, requestor.cache_size());
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());

	// First container requested after 3 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());

	// Second container requested after 6 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());
	// Add a container that won't get added to the queue until later
	auto container5 = inspector.build_container().commit();
	counter.add(container5);
	requestor.request((uptime++)* MS_PER_SEC);
	ASSERT_EQ(2, counter.found());

	// Third container requested after 9 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(3, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(3, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(3, counter.found());

	// Final container requested after 12 seconds and the cache will get
	// update. With 5 containers every 12 seconds, we should see a container
	// get requested every 2.4 seconds
	ASSERT_EQ(1, requestor.cache_size());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(4, counter.found());
	ASSERT_EQ(5, requestor.cache_size());

	counter.reset();
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());

	// First container requested after 3 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());

	// Second container requested after 5 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());

	// Third container requested after 8 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(3, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(3, counter.found());

	// Fourth container requested after 10 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(4, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(4, counter.found());

	// Fifth container requested after 12 seconds and cache updated
	ASSERT_EQ(1, requestor.cache_size());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(5, requestor.cache_size());
	ASSERT_EQ(5, counter.found());

	counter.reset();
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());

	// First container requested after 3 seconds
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());
}

TEST(container_size_requestor_test, big_time_gap)
{
	scoped_configuration config(R"(
container_size_request:
  interval_s: 6
  first_request_delay_s: 4
)");

	// We use the container_counter class to keep track of which containers
	// have been requested.
	container_counter counter;

	sinsp_mock inspector;

	auto container1 = inspector.build_container().commit();
	counter.add(container1);
	auto container2 = inspector.build_container().commit();
	counter.add(container2);
	auto container3 = inspector.build_container().commit();
	counter.add(container3);

	inspector.open();

	// Create a requestor that calls into the container_counter
	container_size_requestor requestor(inspector.m_container_manager,
					   std::bind(& container_counter::update_container_with_size,
						     &counter,
						     std::placeholders::_1,
						     std::placeholders::_2) );

	uint64_t uptime = 40;

	// Call the first time
	requestor.request(uptime * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());

	// Wait longer than the frequency and all containers should get requested
	uptime += 40;
	requestor.request(uptime * MS_PER_SEC);
	ASSERT_EQ(3, counter.found());

	// back to normal
	counter.reset();
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(0, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(1, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());
	requestor.request((uptime++) * MS_PER_SEC);
	ASSERT_EQ(2, counter.found());
}

namespace
{

/**
 * Captures sinsp log messages and looks for a specific message which
 * indicates whether a container size request has occurred. This is useful
 * to validate against the actual container_manager.
 */
class scoped_requestor_log_capture : public scoped_sinsp_logger_capture
{
public:
	/**
	 * Return whether the logs include the message for the given container.
	 */
	bool has(const sinsp_container_info &value)
	{
		LOG_INFO("Looking for: %s", get_container_message(value.m_type, value.m_id).c_str());
		LOG_INFO("Found: %s", get().c_str());
		return find(get_container_message(value.m_type, value.m_id).c_str());
	}
private:
	std::string get_container_message(sinsp_container_type type,
					  const std::string& id)
	{
		// The container engines aren't initialized in sinsp_mock's container_manager.
		// So when a container is requested, the following error message is
		// output. In this test, we look for this error message to validate that
		// the container_size_requestor is functioning the way it is supposed to.
		std::ostringstream stream;
		stream << "Container type " << type << " not found when requesting size for " << id;
		return stream.str();
	}
};

}

// Ensure that this works with the actual container manager
TEST(container_size_requestor_test, real_container_manager)
{
	scoped_configuration config(R"(
container_size_request:
  interval_s: 4
  first_request_delay_s: 1
)");

	sinsp_mock inspector;

	auto container1 = inspector.build_container().commit();
	auto container2 = inspector.build_container().commit();

	inspector.open();

	container_size_requestor requestor(inspector.m_container_manager,
					   std::bind(&sinsp_container_manager::update_container_with_size,
						     &inspector.m_container_manager,
						     std::placeholders::_1,
						     std::placeholders::_2) );
	uint64_t uptime = 1;

	{ // 1
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_FALSE(capture.has(*container2));
	}
	{ // 2
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_FALSE(capture.has(*container2));
	}
	{ // 3
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_FALSE(capture.has(*container2));
	}
	{ // 4
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_TRUE(capture.has(*container2));
	}
	{ // 5
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_FALSE(capture.has(*container2));
	}
	{ // 6
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_TRUE(capture.has(*container1));
		ASSERT_FALSE(capture.has(*container2));
	}
	{ // 7
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_FALSE(capture.has(*container2));
	}
	{ // 8
		scoped_requestor_log_capture capture;
		requestor.request((uptime++) * MS_PER_SEC);
		ASSERT_FALSE(capture.has(*container1));
		ASSERT_TRUE(capture.has(*container2));
	}
}

