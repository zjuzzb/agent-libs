using namespace std;
#include <gtest.h>
#include <chrono>
#include <thread>
#include <list>
#include <sstream>

#include <unistd.h>
#include <ctime>

#include "configuration.h"
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
	struct timespec ts = {.tv_sec = milliseconds / 1000,
	                      .tv_nsec = (milliseconds % 1000) * 1000000, };
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

	for (uint32_t i = 0; i < len; ++i)
	{
		ss << alpha[rand() % alpha.size()];
	}
	return ss.str();
}
}  // End namespace

/**
 * Test the case where the connection manager cannot connect to the collector.
 * The CM should not crash or fall over.
 */
TEST(connection_manager_test, failure_to_connect)
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
		connection_manager cm(&config, &queue, false);
		ASSERT_NO_THROW(cm.test_run());
	});

	// Build the test data
	std::list<std::string> test_data;
	for (uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		test_data.push_back(build_test_string(32));
	}

	// Push to the queue
	for (auto msg : test_data)
	{
		auto it = std::make_shared<serialized_buffer>();
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

TEST(connection_manager_test, connection_timeout)
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

	connection_manager cm(&config, &queue, false);
	cm.set_connection_timeout(4 * 1000 * 1000);

	// Create and spin up the connection manager
	std::thread t([&queue, &config, &cm]()
	{ ASSERT_NO_FATAL_FAILURE(cm.test_run()); });

	while (!cm.m_timed_out)
	{
		msleep(100);
	}

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
		connection_manager cm(&config, &queue, false);
		cm.test_run();
	});

	// Build the test data
	std::list<std::string> test_data;
	for (uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		auto it = std::make_shared<serialized_buffer>();
		it->ts_ns = sinsp_utils::get_current_time_ns();
		it->message_type = draiosproto::message_type::METRICS;
		it->buffer = build_test_string(32);
		dragent_protocol_header_v4* hdr = (dragent_protocol_header_v4*)it->buffer.data();
		hdr->len = 32;
		hdr->len = htonl(hdr->len);
		hdr->version = dragent_protocol::PROTOCOL_VERSION_NUMBER;
		hdr->messagetype = draiosproto::message_type::METRICS;
		test_data.push_back(it->buffer);  // save for comparison
		queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);
		msleep(100);  // sleep for some better interleavings. could probably make more directed with
		              // fault inject infra
	}

	// wait for all the messages to be processed
	for (uint32_t i = 0; queue.size() != 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(queue.size(), 0);

	// wait for all the data to be received
	for (uint32_t i = 0; fc.has_data() != MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(fc.has_data(), MAX_QUEUE_LEN);

	// Shut down all the things
	config.m_terminate = true;
	fc.stop();

	t.join();

	// Validate the messages received by the fake collector
	for (auto sent_data : test_data)
	{
		ASSERT_TRUE(fc.has_data());
		auto b = fc.pop_data();
		EXPECT_EQ(memcmp(b.ptr,
		                 &sent_data.data()[sizeof(dragent_protocol_header_v4)],
		                 32 - sizeof(dragent_protocol_header_v4)),
		          0);
		delete[] b.ptr;
	}
}

TEST(connection_manager_test, message_to_buf_v5)
{
	draiosproto::metrics protobuf;

	// check that we can serialize v4 and v5
	std::shared_ptr<serialized_buffer> v4_output = dragent_protocol::message_to_buffer(
	    1, draiosproto::message_type::METRICS, protobuf, false, false);
	EXPECT_EQ(v4_output->ts_ns, 1);
	EXPECT_EQ(v4_output->message_type, draiosproto::message_type::METRICS);
	std::shared_ptr<serialized_buffer> v5_output = dragent_protocol::message_to_buffer(
	    1, draiosproto::message_type::METRICS, protobuf, true, false);
	EXPECT_EQ(v5_output->ts_ns, 1);
	EXPECT_EQ(v5_output->message_type, draiosproto::message_type::METRICS);
	EXPECT_EQ(v5_output->buffer.size() - v4_output->buffer.size(),
	          sizeof(dragent_protocol_header_v5) - sizeof(dragent_protocol_header_v4));

	// check that the actual header data is right
	auto v4_header = (dragent_protocol_header_v4*)v4_output->buffer.data();
	auto v5_header = (dragent_protocol_header_v5*)v5_output->buffer.data();
	EXPECT_NE(v4_header->len, 0);
	EXPECT_EQ(v4_header->version, dragent_protocol::PROTOCOL_VERSION_NUMBER);
	EXPECT_EQ(v4_header->messagetype, draiosproto::message_type::METRICS);
	EXPECT_NE(v5_header->hdr.len, 0);
	EXPECT_EQ(v5_header->hdr.version, dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);
	EXPECT_EQ(v5_header->hdr.messagetype, draiosproto::message_type::METRICS);

	// check that the the v4 header is at the right spot in the v5 message
	EXPECT_EQ((void*)&v5_header->hdr, (void*)v5_header);

	// naive checks that the serialized data is right
	uint64_t v4_len = htonl(v4_header->len);
	uint64_t v5_len = htonl(v5_header->hdr.len);
	EXPECT_EQ(v5_len - v4_len,
	          sizeof(dragent_protocol_header_v5) - sizeof(dragent_protocol_header_v4));
}

TEST(connection_manager_test, generation)
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
	connection_manager cm(&config, &queue, true);
	std::thread t([&cm]()
	{ cm.test_run(); });

	for (uint32_t i = 0; !cm.is_connected() && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_TRUE(cm.is_connected());
	for (uint32_t i = 0; cm.get_generation() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_generation(), 1);
	ASSERT_EQ(cm.get_sequence(), 0);

	auto it = std::make_shared<serialized_buffer>();
	it->ts_ns = sinsp_utils::get_current_time_ns();
	it->message_type = draiosproto::message_type::METRICS;
	it->buffer = build_test_string(64);
	dragent_protocol_header_v5* hdr = (dragent_protocol_header_v5*)it->buffer.data();
	hdr->hdr.len = 64;
	hdr->hdr.len = htonl(hdr->hdr.len);
	hdr->hdr.version = dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH;
	hdr->hdr.messagetype = draiosproto::message_type::METRICS;
	queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);

	for (uint32_t i = 0; !fc.has_data() && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_sequence(), 1);

	// force reconnect, check that generation increases
	cm.disconnect();
	for (uint32_t i = 0; cm.get_generation() != 2 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_generation(), 2);
	ASSERT_EQ(cm.get_sequence(), 0);

	// Shut down all the things
	config.m_terminate = true;
	fc.stop();

	t.join();
}

TEST(connection_manager_test, v5_end_to_end)
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
	connection_manager cm(&config, &queue, true);
	std::thread t([&cm]()
	{ cm.test_run(); });

	// Build the test data
	std::list<std::string> test_data;
	for (uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		auto it = std::make_shared<serialized_buffer>();
		it->ts_ns = sinsp_utils::get_current_time_ns();
		it->message_type = draiosproto::message_type::METRICS;
		it->buffer = build_test_string(64);
		dragent_protocol_header_v5* hdr = (dragent_protocol_header_v5*)it->buffer.data();
		hdr->hdr.len = 64;
		hdr->hdr.len = htonl(hdr->hdr.len);
		hdr->hdr.version = dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH;
		hdr->hdr.messagetype = draiosproto::message_type::METRICS;
		EXPECT_EQ(it->buffer.size(), 64);
		test_data.push_back(it->buffer);  // save for comparison
		queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);
	}

	// wait for all the messages to be processed
	for (uint32_t i = 0; cm.get_sequence() != MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_sequence(), MAX_QUEUE_LEN);

	// wait for all the data to be received
	for (uint32_t i = 0; fc.has_data() != MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(fc.has_data(), MAX_QUEUE_LEN);

	// Shut down all the things
	config.m_terminate = true;
	fc.stop();

	t.join();

	// Validate the messages received by the fake collector
	int sequence = 0;
	for (auto sent_data : test_data)
	{
		ASSERT_TRUE(fc.has_data());
		fake_collector::buf b = fc.pop_data();
		EXPECT_EQ(memcmp(b.ptr,
		                 &sent_data.data()[sizeof(dragent_protocol_header_v5)],
		                 64 - sizeof(dragent_protocol_header_v5)),
		          0);
		EXPECT_EQ(b.hdr.v5.hdr.len, 64);
		EXPECT_EQ(b.hdr.v5.hdr.version, dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);
		EXPECT_EQ(b.hdr.v5.hdr.messagetype, draiosproto::message_type::METRICS);
		EXPECT_EQ(b.hdr.v5.generation, 1);
		EXPECT_EQ(b.hdr.v5.sequence, ++sequence);
		delete[] b.ptr;
	}
}

class fake_error_message_handler : public connection_manager::message_handler
{
	uint32_t messages_received;
public:
	fake_error_message_handler() : messages_received(0) {}

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override
	{
		++messages_received;
		return true;
	}

	uint32_t num_received() const { return messages_received; }
};

TEST(connection_manager_test, collector_sends_error)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();
	auto mh = std::make_shared<fake_error_message_handler>();

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
	connection_manager cm(&config, &queue, true,
	    {{draiosproto::message_type::ERROR_MESSAGE, mh}});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	// Build a collector message
	draiosproto::error_message err;
	err.set_type(draiosproto::error_type::ERR_PROTO_MISMATCH);

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                     false,
	                                     err);

	ASSERT_TRUE(ret);

	uint32_t loops = 0;
	while (mh->num_received() == 0 && loops < 10000)
	{
		usleep(1000);
		++loops;
	}

	ASSERT_GT(mh->num_received(), 0);

	// Shut down all the things
	config.m_terminate = true;
	fc.stop();

	t.join();
}
