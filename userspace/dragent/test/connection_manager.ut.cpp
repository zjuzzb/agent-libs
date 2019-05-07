using namespace std;
#include <gtest.h>
#include <chrono>
#include <thread>
#include <list>
#include <sstream>

#include <unistd.h>
#include <ctime>

#include "configuration.h"
#include "sinsp_worker.h"
#include "sinsp_mock.h"
#include "watchdog_runnable.h"
#include "connection_manager.h"
#include "fake_collector.h"

#include <Poco/Net/SSLManager.h>

using namespace dragent;
using namespace test_helpers;

namespace
{
/**
 * Sleep for the given number of milliseconds
 *
 * @param milliseconds  Number of ms to sleep for
 */
void msleep(uint32_t milliseconds)
{
    struct timespec ts =
    {
		.tv_sec = milliseconds / 1000,
		.tv_nsec = (milliseconds % 1000) * 1000000,
    };
    nanosleep(&ts, NULL);
}

/**
 * Builds a randomized string of the specified length.
 *
 * @param len  The length of the string to build (not including null terminator)
 *
 * @return The requested string
 */
std::string build_test_string(uint32_t len)
{
	static const std::string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::stringstream ss;

	for(uint32_t i = 0; i < len; ++i)
	{
		ss << alpha[rand() % alpha.size()];
	}
	return ss.str();
}
} // End namespace

/**
 * Test the case where the connection manager cannot connect to the collector.
 * The CM should not crash or fall over.
 */
TEST(connection_manager_test, DISABLED_failure_to_connect)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = 7357;
	config.m_ssl_enabled = false;
	config.m_transmitbuffer_size = DEFAULT_DATA_SOCKET_BUF_SIZE;
	config.m_terminate = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	thread t([&queue, &config]()
	{
	connection_manager cm(&config,
						  &queue,
						  nullptr,  // sinsp_worker
						  nullptr); // capture_job_handler
		ASSERT_NO_THROW(cm.test_run());
	});

	// Build the test data
	std::list<std::string> test_data;
	for(uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		test_data.push_back(build_test_string(32));
	}

	// Push to the queue
	for(auto msg: test_data)
	{
		auto it = std::make_shared<protocol_queue_item>();
		it->ts_ns = sinsp_utils::get_current_time_ns();
		it->message_type = draiosproto::message_type::METRICS;
		it->buffer = msg;
		queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);
		msleep(100);
	}

	// Shut down the CM
	config.m_terminate = true;

	t.join();
}

TEST(connection_manager_test, DISABLED_connection_timeout)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Set the config for the CM
	// Note that by connecting to sysdig.com on a weird port, the firewall
	// will drop the SYN and this will cause a connect timeout.
	config.m_server_addr = "www.sysdig.com";
	config.m_server_port = 81;
	config.m_ssl_enabled = false;
	config.m_transmitbuffer_size = DEFAULT_DATA_SOCKET_BUF_SIZE;
	config.m_terminate = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	sinsp_worker* worker = nullptr;
	capture_job_handler* capture_handler = nullptr;
	connection_manager cm(&config,
						  &queue,
						  worker,
						  capture_handler);
	cm.set_connection_timeout(6 * 1000 * 1000);

	// Create and spin up the connection manager
	std::thread t([&queue, &config, &cm]()
	{
		ASSERT_NO_FATAL_FAILURE(cm.test_run());
	});

	sleep(7);

	// Shut down all the things
	config.m_terminate = true;

	t.join();
}

TEST(connection_manager_test, connect_transmit)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc;
	fc.start(0);

	ASSERT_GT(fc.get_port(), 0);

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;
	config.m_transmitbuffer_size = DEFAULT_DATA_SOCKET_BUF_SIZE;
	config.m_terminate = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);


	// Create and spin up the connection manager
	std::thread t([&queue, &config]()
	{
		// The sinsp_worker and c_j_h are only used when processing
		// push messages from the backend. For the moment these can
		// be null.
		sinsp_worker* worker = nullptr;
		capture_job_handler* capture_handler = nullptr;
		connection_manager cm(&config,
		                      &queue,
		                      worker,
		                      capture_handler);
		cm.test_run();
	});

	// Build the test data
	std::list<std::string> test_data;
	for(uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		test_data.push_back(build_test_string(32));
	}

	// Push to the queue
	for(auto msg: test_data)
	{
		auto it = std::make_shared<protocol_queue_item>();
		it->ts_ns = sinsp_utils::get_current_time_ns();
		it->message_type = draiosproto::message_type::METRICS;
		it->buffer = msg;

		// Add the length to the front of the string
		// (Almost as if this were a real protocol!)
		std::stringstream ss;
		ASSERT_LT(msg.length(), 10000);
		ss << std::setfill('0') << std::setw(4) << msg.length() << ":" << msg;
		it->buffer = ss.str();
		queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);
		msleep(100);
	}

	// Shut down all the things
	config.m_terminate = true;
	fc.stop();

	t.join();

	// Validate the messages received by the fake collector
	for(auto sent_data: test_data)
	{
		ASSERT_TRUE(fc.has_data());
		auto b = fc.pop_data();
		std::string received_data(reinterpret_cast<char*>(b.ptr));
		ASSERT_EQ(sent_data, received_data);
		delete[] b.ptr;
	}
}
