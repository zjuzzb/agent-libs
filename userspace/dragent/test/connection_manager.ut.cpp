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
#include "handshake.pb.h"
#include "draios.pb.h"

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
	fake_collector fc(false);
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
		EXPECT_EQ(memcmp(b.ptr, sent_data.data(), 32), 0);
		delete[] b.ptr;
	}
}

// XXX TODO Re-enable once v5 protocol is ready
TEST(connection_manager_test, DISABLED_generation)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false);
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
	for (uint32_t i = 0; cm.get_generation() == 1 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_generation(), 2);
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
	ASSERT_EQ(cm.get_generation(), 3);
	ASSERT_EQ(cm.get_sequence(), 1);

	// Shut down all the things
	config.m_terminate = true;
	fc.stop();

	t.join();
}

TEST(connection_manager_test, DISABLED_v5_end_to_end)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false);
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

class counting_message_handler : public connection_manager::message_handler
{
	uint32_t messages_received;
public:
	counting_message_handler() : messages_received(0) {}

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
	auto mh = std::make_shared<counting_message_handler>();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false);
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

template<typename message_type>
class generic_handler : public connection_manager::message_handler
{
public:
	generic_handler() {}
	bool handle_message(const draiosproto::message_type,
						uint8_t* buffer,
						size_t buffer_size) override
	{
		dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &message);
		message_received = true;
		return false;
	}

	message_type message;
	bool message_received = false;
};

TEST(fake_collector_test, DISABLED_protocol_init_response)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);
	ASSERT_GT(fc.get_port(), 0);

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;
	config.m_transmitbuffer_size = DEFAULT_DATA_SOCKET_BUF_SIZE;
	config.m_terminate = false;

	auto pirh = std::make_shared<generic_handler<draiosproto::protocol_init_response>>();
	protocol_queue queue(MAX_QUEUE_LEN);
	connection_manager cm(&config,
						  &queue,
						  true,
						  {{draiosproto::message_type::PROTOCOL_INIT_RESP, pirh}});
	std::thread t([&cm]()
	{
		cm.test_run();
	});

	for (uint32_t i = 0; i < 5000 && !pirh->message_received; i++)
	{
		usleep(1000);
	}
	ASSERT_TRUE(pirh->message_received);
	EXPECT_EQ(pirh->message.protocol_version(), 1);

	config.m_terminate = true;
	fc.stop();
	t.join();
}

TEST(fake_collector_test, DISABLED_protocol_handshake_v1)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);
	ASSERT_GT(fc.get_port(), 0);

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;
	config.m_transmitbuffer_size = DEFAULT_DATA_SOCKET_BUF_SIZE;
	config.m_terminate = false;

	auto pirh = std::make_shared<generic_handler<draiosproto::protocol_init_response>>();
	auto hrh = std::make_shared<generic_handler<draiosproto::handshake_v1_response>>();
	protocol_queue queue(MAX_QUEUE_LEN);
	connection_manager cm(&config,
						  &queue,
						  true,
						  {{draiosproto::message_type::PROTOCOL_INIT_RESP, pirh},
						   {draiosproto::message_type::PROTOCOL_HANDSHAKE_V1_RESP, hrh}});
	std::thread t([&cm]()
	{
		cm.test_run();
	});

	// test will go like this:
	// wait for hand shake to complete, set the ack to something non-1's
	// force a reconnect
	// check that we get the right response
	for (uint32_t i = 0; i < 5000 && !hrh->message_received; i++)
	{
		usleep(1000);
	}
	ASSERT_TRUE(hrh->message_received);

	// reset the handshake response
	hrh->message_received = false;

	// make the gen/seql in the fc bigger
	fc.set_last_ack(5, 10);

	// force reconnect
	cm.disconnect();

	// wait for header again
	for (uint32_t i = 0; i < 5000 && !hrh->message_received; i++)
	{
		usleep(1000);
	}
	ASSERT_TRUE(hrh->message_received);
	EXPECT_EQ(hrh->message.last_acked_gen_num(), 5);
	EXPECT_EQ(hrh->message.last_acked_seq_num(), 10);
	EXPECT_EQ(hrh->message.compression(), draiosproto::compression::COMPRESSION_GZIP);
	EXPECT_EQ(hrh->message.agg_interval(), 10);
	EXPECT_FALSE(hrh->message.agg_context().enforce());

	config.m_terminate = true;
	fc.stop();
	t.join();
}

TEST(fake_collector_test, DISABLED_ack)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration::m_terminate = false;
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);
	ASSERT_GT(fc.get_port(), 0);

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;
	config.m_transmitbuffer_size = DEFAULT_DATA_SOCKET_BUF_SIZE;
	config.m_terminate = false;

	auto pirh = std::make_shared<generic_handler<draiosproto::protocol_init_response>>();
	auto hrh = std::make_shared<generic_handler<draiosproto::handshake_v1_response>>();
	auto ah = std::make_shared<counting_message_handler>();
	protocol_queue queue(MAX_QUEUE_LEN);
	connection_manager cm(&config,
						  &queue,
						  true,
						  {{draiosproto::message_type::PROTOCOL_INIT_RESP, pirh},
						   {draiosproto::message_type::PROTOCOL_HANDSHAKE_V1_RESP, hrh},
						   {draiosproto::message_type::METRICS_ACK, ah}});
	std::thread t([&cm]()
	{
		cm.test_run();
	});

	// test will go like this:
	// wait for hand shake to complete, set the ack to something non-1's
	// force a reconnect
	// check that we get the right response
	for (uint32_t i = 0; i < 5000 && !hrh->message_received; i++)
	{
		usleep(1000);
	}
	ASSERT_TRUE(hrh->message_received);

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

	for (uint32_t i = 0; i < 5000 && ah->num_received() == 0; i++)
	{
		usleep(1000);
	}
	ASSERT_NE(ah->num_received(), 0);


	config.m_terminate = true;
	fc.stop();
	t.join();
}
