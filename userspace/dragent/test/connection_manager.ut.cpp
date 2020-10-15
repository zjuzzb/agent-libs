using namespace std;
#include <gtest.h>
#include <chrono>
#include <thread>
#include <list>
#include <sstream>

#include <unistd.h>
#include <ctime>

#include "configuration.h"
#include "exit_code.h"
#include "sinsp_mock.h"
#include "watchdog_runnable.h"
#include "connection_manager.h"
#include "cm_proxy_tunnel.h"
#include "fake_collector.h"
#include "handshake.pb.h"
#include "draios.pb.h"
#include "dragent_settings_interface.h"
#include "scoped_config.h"

#include "protobuf_metric_serializer.h"
#include "protocol_handler.h"
#include "http_server.h"
#include "running_state_fixture.h"
#include "async_aggregator.h"
#include "watchdog_runnable_pool.h"
#include "utils.h"

#include <Poco/Net/SSLManager.h>
#include <Poco/Net/NetException.h>
using namespace dragent;
using namespace test_helpers;

namespace
{

/**
 * Reset the running_state after each test
 */
class connection_manager_fixture : public running_state_fixture 
{
public:
	connection_manager_fixture() {}
};

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

draiosproto::metrics* build_test_metrics(uint64_t index)
{
	draiosproto::metrics* test_metrics = new draiosproto::metrics();
	test_metrics->set_machine_id(build_test_string(32));
	test_metrics->set_customer_id(build_test_string(64));
	test_metrics->set_timestamp_ns(1000);
	test_metrics->set_index(index);
	return test_metrics;
}
}  // End namespace

/**
 * Test the case where the connection manager cannot connect to the collector.
 * The CM should not crash or fall over.
 */
TEST_F(connection_manager_fixture, failure_to_connect)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = 7357;
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	thread t([&queue, &config]()
	{
		connection_manager cm(&config, &queue, {4});
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
	running_state::instance().shut_down();

	t.join();
}

TEST_F(connection_manager_fixture, connection_timeout)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Set the config for the CM
	// Note that by connecting to sysdig.com on a weird port, the firewall
	// will drop the SYN and this will cause a connect timeout.
	config.m_server_addr = "www.sysdig.com";
	config.m_server_port = 81;
	config.m_ssl_enabled = false;

	test_helpers::scoped_config<uint32_t> conn_timeout("connect_timeout", 1500);
	
	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	connection_manager cm(&config, &queue, {4});

	// Create and spin up the connection manager
	std::thread t([&queue, &config, &cm]()
	{ ASSERT_NO_FATAL_FAILURE(cm.test_run()); });

	while (!cm.m_timed_out)
	{
		msleep(100);
	}

	// Shut down all the things
	running_state::instance().shut_down();

	t.join();
}

TEST_F(connection_manager_fixture, connect_transmit)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
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

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	std::thread t([&queue, &config]()
	{
		connection_manager cm(&config, &queue, {4});
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
		msleep(100);  // sleep for some better interleavings. could
		              // probably make more directed with
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
	ASSERT_EQ(0, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
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

TEST_F(connection_manager_fixture, generation)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
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

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	connection_manager cm(&config, &queue, {5});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	for (uint32_t i = 0; !cm.is_connected() && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_TRUE(cm.is_connected());

	ASSERT_EQ(cm.get_generation(), 1);
	ASSERT_EQ(cm.get_sequence(), 1);

	auto it = std::make_shared<serialized_buffer>();
	it->ts_ns = sinsp_utils::get_current_time_ns();
	it->message_type = draiosproto::message_type::METRICS;
	it->buffer = build_test_string(64);
	queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);

	for (uint32_t i = 0; cm.get_sequence() < 2 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_sequence(), 2);

	// force reconnect, check that generation increases
	fc.drop_connection();

	// Need to send another metrics message so CM discovers the connection drop
	it = std::make_shared<serialized_buffer>();
	it->ts_ns = sinsp_utils::get_current_time_ns();
	it->message_type = draiosproto::message_type::METRICS;
	it->buffer = build_test_string(64);
	queue.put(it, protocol_queue::BQ_PRIORITY_HIGH);

	// Wait for CM to reconnect (this requires some fiddling)
	for (uint32_t i = 0; cm.get_generation() < 2 && i < 10000; ++i)
	{
		usleep(1000);
	}
	for (uint32_t i = 0; !cm.is_connected() && i < 10000; ++i)
	{
		usleep(1000);
	}

	ASSERT_TRUE(cm.is_connected());
	ASSERT_EQ(cm.get_generation(), 2);
	ASSERT_EQ(cm.get_sequence(), 1);
	ASSERT_EQ(1, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
}

class bogus_capture_stats_source : public capture_stats_source
{
	void get_capture_stats(scap_stats *stats) const override
	{
		memset(stats, 0, sizeof(*stats));
	}
};

TEST_F(connection_manager_fixture, v5_end_to_end)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();
	std::atomic<bool> metrics_sent(false);

	// Create the shared blocking queues
	flush_queue fqueue(MAX_QUEUE_LEN);
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// All the stuff to build a serializer
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<bogus_capture_stats_source>();
	protocol_handler ph(pqueue);
	auto compressor = gzip_protobuf_compressor::get(-1);

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);

	ASSERT_GT(fc.get_port(), 0);

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create and spin up the connection manager
	connection_manager cm(&config, &pqueue, {5});
	protobuf_metric_serializer serializer(stats_source,
	                                      "",
	                                      ph,
	                                      &fqueue,
	                                      &pqueue,
	                                      compressor,
	                                      &cm);

	std::thread ct([&cm]()
	{
		cm.test_run();
	});

	std::thread st([&serializer]()
	{
		serializer.test_run();
	});

	// Build the test data
	std::list<draiosproto::metrics> test_data;
	for (uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		draiosproto::metrics* m = build_test_metrics(i + 1);
		serializer.serialize(std::make_shared<flush_data_message>(
		                         1000 + i,
		                         &metrics_sent,
		                         std::unique_ptr<draiosproto::metrics>(m),
		                         MAX_QUEUE_LEN,
		                         0,
		                         1.0,
		                         1,
		                         0));

		test_data.push_back(*m);  // save for comparison
	}

	// wait for all the messages to be processed
	for (uint32_t i = 0; cm.get_sequence() <= MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_sequence(), MAX_QUEUE_LEN + 1);

	// Pop the handshake messages off the data queue
	ASSERT_GT(fc.has_data(), 2);
	(void)fc.pop_data();
	(void)fc.pop_data();

	// wait for all the data to be received
	for (uint32_t i = 0; fc.has_data() < MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), MAX_QUEUE_LEN);
	ASSERT_EQ(0, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	ct.join();
	serializer.stop();
	st.join();

	// Validate the messages received by the fake collector
	for (auto sent_data : test_data)
	{
		ASSERT_TRUE(fc.has_data());
		fake_collector::buf b = fc.pop_data();

		draiosproto::metrics received_metrics;
		dragent_protocol::buffer_to_protobuf(b.ptr,
		                                     b.payload_len,
		                                     &received_metrics,
		                                     protocol_compression_method::GZIP);

		EXPECT_EQ(sent_data.timestamp_ns(), received_metrics.timestamp_ns());
		EXPECT_EQ(sent_data.customer_id(), received_metrics.customer_id());
		EXPECT_EQ(sent_data.machine_id(), received_metrics.machine_id());
		EXPECT_EQ(sent_data.index(), received_metrics.index());
	}
}

class counting_message_handler : public connection_manager::message_handler
{
	uint32_t messages_received;
	bool token_mismatch;
	std::string dump_token;
public:
	counting_message_handler() :
	    messages_received(0),
	    token_mismatch(false),
	    dump_token("")
	{}

	counting_message_handler(std::string token) :
	    messages_received(0),
	    token_mismatch(false),
	    dump_token(token)
	{}

	bool handle_message(const draiosproto::message_type type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override
	{
		if (type == draiosproto::message_type::DUMP_REQUEST_START)
		{
			// Extract the error
			draiosproto::dump_request_start msg;
			dragent_protocol::buffer_to_protobuf(buffer,
			                                     buffer_size,
			                                     &msg,
			                                     protocol_compression_method::GZIP);

			if (!dump_token.empty() && msg.token() != dump_token)
			{
				token_mismatch = true;
			}
		}

		++messages_received;
		return true;
	}

	uint32_t num_received() const { return messages_received; }
	bool has_token_mismatch() const { return token_mismatch; }
};

bool test_collector_sends_message(dragent_protocol::protocol_version ver)
{
	const size_t MAX_QUEUE_LEN = 64;
	const std::string token = "DEADBEEF";
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();
	auto mh = std::make_shared<counting_message_handler>(token);

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(ver == dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH);
	fc.start(0);
	if (fc.get_port() == 0)
	{
		return false;
	}

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	connection_manager cm(&config, &queue, {ver},
	    {{draiosproto::message_type::DUMP_REQUEST_START, mh}});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	// If v5, we have to wait for the connection to be established
	uint32_t loops = 0;
	while(cm.get_state() != cm_state_machine::state::STEADY_STATE && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	if (cm.get_state() != cm_state_machine::state::STEADY_STATE)
	{
		return false;
	}

	// Build a collector message
	draiosproto::dump_request_start dump_start;
	dump_start.set_timestamp_ns(sinsp_utils::get_current_time_ns());
	dump_start.set_machine_id("0");
	dump_start.set_token(token);

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::DUMP_REQUEST_START,
	                                     ver,
	                                     dump_start);

	if (!ret)
	{
		return false;
	}

	loops = 0;
	while (mh->num_received() == 0 && loops < 10000)
	{
		usleep(1000);
		++loops;
	}

	if (mh->num_received() == 0)
	{
		return false;
	}

	if (mh->has_token_mismatch())
	{
		return false;
	}

	if (fc.get_num_disconnects() > 0)
	{
		return false;
	}

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
	return true;
}

TEST_F(connection_manager_fixture, collector_sends_message_v4)
{
	ASSERT_TRUE(test_collector_sends_message(4));
}

TEST_F(connection_manager_fixture, collector_sends_message_v5)
{
	ASSERT_TRUE(test_collector_sends_message(5));
}

TEST_F(connection_manager_fixture, basic_connect_with_handshake)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	connection_manager cm(&config, &queue, {5});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	uint32_t loops = 0;
	while(cm.get_state() != cm_state_machine::state::STEADY_STATE && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());

	ASSERT_EQ(fc.has_data(), 2);

	// Check each of the received messages
	fake_collector::buf b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_INIT, b.hdr.v4.messagetype);

	// Validate the protocol_init message
	draiosproto::protocol_init pi;
	dragent_protocol::buffer_to_protobuf(b.ptr,
	                                     b.payload_len,
	                                     &pi,
	                                     protocol_compression_method::NONE);

	ASSERT_EQ(1, pi.supported_protocol_versions().size());
	dragent_protocol::protocol_version version = pi.supported_protocol_versions()[0];
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH, version);
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH,
	          cm.get_negotiated_protocol_version());

	// Validate the handshake phase 2 message
	b = fc.pop_data();
	uint64_t hdr_gen = ntohll(b.hdr.v5.generation);
	uint64_t hdr_seq = ntohll(b.hdr.v5.sequence);
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_HANDSHAKE_V1, b.hdr.v4.messagetype);
	ASSERT_EQ(1, hdr_gen);
	ASSERT_EQ(1, hdr_seq);

	draiosproto::handshake_v1 h;
	dragent_protocol::buffer_to_protobuf(b.ptr,
	                                     b.payload_len,
	                                     &h,
	                                     protocol_compression_method::NONE);

	bool gzip = false;
	bool none = false;
	for (auto i : h.supported_compressions())
	{
		if (i == draiosproto::compression::COMPRESSION_GZIP)
		{
			gzip = true;
		}
		else if (i == draiosproto::compression::COMPRESSION_NONE)
		{
			none = true;
		}
		else
		{
			// Agent doesn't currently support anything else
			ASSERT_TRUE(i == draiosproto::compression::COMPRESSION_GZIP ||
			            i == draiosproto::compression::COMPRESSION_NONE);
		}
	}
	ASSERT_TRUE(gzip && none);

	bool ai_10 = false;
	for (auto i : h.supported_agg_intervals())
	{
		if (i == 10)
		{
			ai_10 = true;
		}
		else
		{
			// Currently only 10s is supported
			ASSERT_EQ(10, i);
		}
	}

	ASSERT_TRUE(ai_10);
	ASSERT_EQ(0, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
}

TEST_F(connection_manager_fixture, metrics_ack)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	uint64_t index = 1;
	config.init();
	std::atomic<bool> metrics_sent(false);

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.delay_acks(true);
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queues
	flush_queue fqueue(MAX_QUEUE_LEN);
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// All the stuff to build a serializer
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<bogus_capture_stats_source>();
	protocol_handler ph(pqueue);
	auto compressor = gzip_protobuf_compressor::get(-1);

	// Create and spin up the connection manager
	connection_manager cm(&config, &pqueue, {5});
	protobuf_metric_serializer serializer(stats_source,
	                                      "",
	                                      ph,
	                                      &fqueue,
	                                      &pqueue,
	                                      compressor,
	                                      &cm);

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	std::thread st([&serializer]()
	{
		serializer.test_run();
	});

	for(uint32_t loops = 0; !cm.is_connected() && loops < 10000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(cm.is_connected());

	// Build and send a fake metrics message
	auto metrics = build_test_metrics(index++);
	serializer.serialize(std::make_shared<flush_data_message>(
	                         sinsp_utils::get_current_time_ns(),
	                         &metrics_sent,
	                         std::unique_ptr<draiosproto::metrics>(metrics),
	                         MAX_QUEUE_LEN,
	                         0,
	                         1.0,
	                         1,
	                         0));

	// wait for all the data to be received
	const uint32_t total_messages = 3; // Two HS + 1 metrics
	for (uint32_t i = 0; fc.has_data() < total_messages && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(0, pqueue.size());
	ASSERT_EQ(fc.has_data(), total_messages);

	// Check each of the received messages
	fake_collector::buf b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_INIT, b.hdr.v4.messagetype);

	b = fc.pop_data();
	uint64_t hs_gen = ntohll(b.hdr.v5.generation);
	uint64_t hs_seq = ntohll(b.hdr.v5.sequence);
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_HANDSHAKE_V1, b.hdr.v4.messagetype);
	ASSERT_EQ(1, hs_gen);
	ASSERT_EQ(1, hs_seq);

	b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::METRICS, b.hdr.v4.messagetype);
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH, b.hdr.v4.version);

	// It's remotely possible that the CM hasn't updated unacked messages yet
	for(uint32_t loops = 0; cm.num_unacked_messages() < 1 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, cm.num_unacked_messages());
	dragent_protocol_header_v5 hdr = cm.first_unacked_header();
	ASSERT_EQ(draiosproto::message_type::METRICS, hdr.hdr.messagetype);
	uint64_t gen = ntohll(hdr.generation);
	uint64_t seq = ntohll(hdr.sequence);
	ASSERT_EQ(1, gen);
	ASSERT_EQ(1, seq);
	fc.delay_acks(false);

	// Wait for ack to be processed
	for (uint32_t i = 0; cm.num_unacked_messages() > 0 && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(0, cm.num_unacked_messages());
	ASSERT_EQ(0, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
	serializer.stop();
	st.join();
}

TEST_F(connection_manager_fixture, change_aggregation_interval)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create a connection manager (don't need to start it for this test)
	connection_manager cm(&config, &queue, {5});
	aggregation_interval_source* src = &cm;

	ASSERT_EQ(chrono::seconds::max(), cm.get_negotiated_aggregation_interval());

	uint32_t new_interval = 10;
	cm.set_aggregation_interval(new_interval);

	ASSERT_EQ(new_interval, src->get_negotiated_aggregation_interval().count());

}

TEST_F(connection_manager_fixture, handshake_version_negotiation_failure)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false); // Don't auto respond
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	connection_manager cm(&config, &queue, {5});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	for(uint32_t loops = 0; fc.has_data() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), 1);

	// Should have gotten a PROTOCOL_INIT message
	fake_collector::buf b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_INIT, b.hdr.v4.messagetype);

	// Validate the protocol_init message
	draiosproto::protocol_init pi;
	dragent_protocol::buffer_to_protobuf(b.ptr,
	                                     b.payload_len,
	                                     &pi,
	                                     protocol_compression_method::NONE);

	ASSERT_EQ(1, pi.supported_protocol_versions().size());
	dragent_protocol::protocol_version version = pi.supported_protocol_versions()[0];
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH, version);

	// Now send a response with a bogus version number
	draiosproto::protocol_init_response pir;
	pir.set_timestamp_ns(pi.timestamp_ns() + 1);
	pir.set_machine_id(pi.machine_id());
	pir.set_customer_id(pi.customer_id());
	pir.set_protocol_version(3); // Unsupported version number
	fc.send_collector_message(draiosproto::message_type::PROTOCOL_INIT_RESP,
	                          4,
	                          pir,
	                          0,
	                          0,
	                          protobuf_compressor_factory::get_default());


	for(uint32_t loops = 0; fc.get_num_disconnects() < 1 && loops < 5000 ; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, fc.get_num_disconnects());

	// The CM should cycle the connection and retry the handshake
	for(uint32_t loops = 0; fc.has_data() < 1 && loops < 5000 ; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, fc.get_num_disconnects());

	// Shut down all the things (this will conveniently also test terminate
	// in the middle of a handshake)
	running_state::instance().shut_down();
	fc.stop();

	t.join();
}

TEST_F(connection_manager_fixture, gen_seq_ordering)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create a connection manager (no need to start it up)
	connection_manager cm(&config, &queue, {5});

	dragent_protocol_header_v5 ack_header;
	dragent_protocol_header_v5 metrics_header;

	// TEST 1: both equal
	ack_header.generation = metrics_header.generation = 1;
	ack_header.sequence = metrics_header.sequence = 5;

	ASSERT_EQ(metrics_header.generation, ack_header.generation);
	ASSERT_EQ(metrics_header.sequence, ack_header.sequence);
	ASSERT_TRUE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 2: seq less than ack
	metrics_header.sequence = 4;
	ASSERT_EQ(metrics_header.generation, ack_header.generation);
	ASSERT_LT(metrics_header.sequence, ack_header.sequence);
	ASSERT_TRUE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 3: seq greater than ack
	metrics_header.sequence = 174;
	ASSERT_EQ(metrics_header.generation, ack_header.generation);
	ASSERT_GT(metrics_header.sequence, ack_header.sequence);
	ASSERT_FALSE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 4: gen less than ack, seq equal
	metrics_header.sequence = ack_header.sequence;
	ack_header.generation = 2;
	ASSERT_LT(metrics_header.generation, ack_header.generation);
	ASSERT_EQ(metrics_header.sequence, ack_header.sequence);
	ASSERT_TRUE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 5: gen greater than ack, seq equal
	metrics_header.generation = 4;
	ASSERT_GT(metrics_header.generation, ack_header.generation);
	ASSERT_EQ(metrics_header.sequence, ack_header.sequence);
	ASSERT_FALSE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 6: gen greater than ack, seq greater than ack
	metrics_header.generation = 4;
	metrics_header.sequence = 190;
	ack_header.generation = 2;
	ack_header.sequence = 118;
	ASSERT_GT(metrics_header.generation, ack_header.generation);
	ASSERT_GT(metrics_header.sequence, ack_header.sequence);
	ASSERT_FALSE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 7: gen less than ack, seq less than ack
	ack_header.generation = 1809;
	ack_header.sequence = 28001;
	ASSERT_LT(metrics_header.generation, ack_header.generation);
	ASSERT_LT(metrics_header.sequence, ack_header.sequence);
	ASSERT_TRUE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));

	// TEST 8: gen less than ack, seq greater than ack
	ack_header.sequence = 38;
	ASSERT_LT(metrics_header.generation, ack_header.generation);
	ASSERT_GT(metrics_header.sequence, ack_header.sequence);
	ASSERT_TRUE(cm.test_sequence_less_or_equal(&metrics_header, &ack_header));
}

TEST_F(connection_manager_fixture, legacy_fallback)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	uint64_t index = 1;
	config.init();
	std::atomic<bool> metrics_sent(false);

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false); // Don't auto respond
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queues
	flush_queue fqueue(MAX_QUEUE_LEN);
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// All the stuff to build a serializer
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<bogus_capture_stats_source>();
	protocol_handler ph(pqueue);
	auto compressor = gzip_protobuf_compressor::get(-1);

	// Create and spin up the connection manager
	connection_manager cm(&config, &pqueue, {5});
	protobuf_metric_serializer serializer(stats_source,
	                                      "",
	                                      ph,
	                                      &fqueue,
	                                      &pqueue,
	                                      compressor,
	                                      &cm);

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	std::thread st([&serializer]()
	{
		serializer.test_run();
	});

	// Put some metrics on the CM's queue
	auto metrics = build_test_metrics(index++);
	serializer.serialize(std::make_shared<flush_data_message>(
	                         sinsp_utils::get_current_time_ns(),
	                         &metrics_sent,
	                         std::unique_ptr<draiosproto::metrics>(metrics),
	                         MAX_QUEUE_LEN,
	                         0,
	                         1.0,
	                         1,
	                         0));

	// Wait for the CM to start the handshake
	for(uint32_t loops = 0; fc.has_data() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), 1);

	ASSERT_EQ(0, cm.get_negotiated_protocol_version());

	// Should have gotten a PROTOCOL_INIT message
	fake_collector::buf b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_INIT, b.hdr.v4.messagetype);

	// Validate the protocol_init message
	draiosproto::protocol_init pi;
	dragent_protocol::buffer_to_protobuf(b.ptr,
	                                     b.payload_len,
	                                     &pi,
	                                     protocol_compression_method::NONE);

	ASSERT_EQ(1, pi.supported_protocol_versions().size());
	dragent_protocol::protocol_version version = pi.supported_protocol_versions()[0];
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH, version);

	// Now send a PROTO_MISMATCH error
	draiosproto::error_message err;
	err.set_type(draiosproto::error_type::ERR_PROTO_MISMATCH);
	err.set_description("CM UNIT TEST");

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                     dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                     err);
	ASSERT_TRUE(ret);

	// Ensure the CM drops into legacy mode
	for(uint32_t loops = 0;
	    cm.get_state() != cm_state_machine::state::STEADY_STATE && loops < 10000;
	    ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());
	ASSERT_EQ(4, cm.get_negotiated_protocol_version());
	ASSERT_EQ(0, cm.get_negotiated_aggregation_interval().count());
	ASSERT_EQ(0, fc.get_num_disconnects());

	// The CM should have cleared its queue
	ASSERT_EQ(0, pqueue.size());
	ASSERT_EQ(0, fc.has_data());

	// More metrics for the CM
	metrics = build_test_metrics(index++);
	serializer.serialize(std::make_shared<flush_data_message>(
	                         sinsp_utils::get_current_time_ns(),
	                         &metrics_sent,
	                         std::unique_ptr<draiosproto::metrics>(metrics),
	                         MAX_QUEUE_LEN,
	                         0,
	                         1.0,
	                         1,
	                         0));

	// The CM should now be sending metrics with no further protocol messages
	for(uint32_t loops = 0; fc.has_data() < 1 && loops < 5000 ; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, fc.has_data());

	b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::METRICS, b.hdr.v4.messagetype);
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER, b.hdr.v4.version);

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
	serializer.stop();
	st.join();
}

TEST_F(connection_manager_fixture, test_error_message_handler)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	connection_manager cm(&config, &queue, {5});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	// Wait for the connection to be established
	uint32_t loops = 0;
	while(cm.get_state() != cm_state_machine::state::STEADY_STATE && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());

	// Build a collector message
	draiosproto::error_message err;
	err.set_type(draiosproto::error_type::ERR_PROTO_MISMATCH);

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                     dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                     err);

	ASSERT_TRUE(ret);

	loops = 0;
	while (fc.get_num_disconnects() == 0 && loops < 10000)
	{
		usleep(1000);
		++loops;
	}

	ASSERT_EQ(1, fc.get_num_disconnects());
	ASSERT_FALSE(cm.is_connected());
	ASSERT_TRUE(running_state::instance().is_terminated());
	ASSERT_EQ(running_state::instance().exit_code(), dragent::exit_code::RESTART);

	// Shut down all the things
	fc.stop();

	t.join();
}

TEST_F(connection_manager_fixture, backoff)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false); // Don't auto respond
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queues
	flush_queue fqueue(MAX_QUEUE_LEN);
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// All the stuff to build a serializer
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<bogus_capture_stats_source>();
	protocol_handler ph(pqueue);
	auto compressor = gzip_protobuf_compressor::get(-1);

	// Create and spin up the connection manager
	connection_manager cm(&config, &pqueue, {5});
	protobuf_metric_serializer serializer(stats_source,
	                                      "",
	                                      ph,
	                                      &fqueue,
	                                      &pqueue,
	                                      compressor,
	                                      &cm);

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	std::thread st([&serializer]()
	{
		serializer.test_run();
	});

	// Wait for the CM to start the handshake
	for(uint32_t loops = 0; fc.has_data() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), 1);

	// Ensure it's a PROTOCOL_INIT message
	fake_collector::buf b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_INIT, b.hdr.v4.messagetype);

	draiosproto::protocol_init pi;
	dragent_protocol::buffer_to_protobuf(b.ptr,
	                                     b.payload_len,
	                                     &pi,
	                                     protocol_compression_method::NONE);

	ASSERT_EQ(1, pi.supported_protocol_versions().size());
	dragent_protocol::protocol_version version = pi.supported_protocol_versions()[0];
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH, version);

	ASSERT_EQ(0, fc.get_num_disconnects());
	ASSERT_EQ(0, cm.get_reconnect_interval());

	// Now send an INVALID CUSTOMER KEY error
	draiosproto::error_message err;
	err.set_type(draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY);
	err.set_description("CM UNIT TEST");

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                     dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                     err);
	ASSERT_TRUE(ret);

	// Ensure the CM drops the connection
	for(uint32_t loops = 0; fc.get_num_disconnects() < 1 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	// The backoff should now be 1
	ASSERT_EQ(1, cm.get_reconnect_interval());

	ASSERT_EQ(0, fc.has_data());
	// Wait for the CM to start the handshake again
	for(uint32_t loops = 0; fc.has_data() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), 1);

	// Now send the INVALID CUSTOMER KEY error again
	err.set_type(draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY);
	err.set_description("CM UNIT TEST");
	ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                err);
	ASSERT_TRUE(ret);

	// Ensure the CM drops the connection yet again
	for(uint32_t loops = 0; fc.get_num_disconnects() < 2 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	// The backoff should now be 2
	ASSERT_EQ(2, cm.get_reconnect_interval());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
	serializer.stop();
	st.join();
}

TEST_F(connection_manager_fixture, backoff_recovery_v4)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	std::atomic<bool> metrics_sent(false);
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(false); // Don't auto respond
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queues
	flush_queue fqueue(MAX_QUEUE_LEN);
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// All the stuff to build a serializer
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<bogus_capture_stats_source>();
	protocol_handler ph(pqueue);
	auto compressor = gzip_protobuf_compressor::get(-1);

	// Create and spin up the connection manager
	connection_manager cm(&config, &pqueue, {4});
	cm.set_working_interval(1); // Don't want to wait for 10 seconds
	protobuf_metric_serializer serializer(stats_source,
	                                      "",
	                                      ph,
	                                      &fqueue,
	                                      &pqueue,
	                                      compressor,
	                                      &cm);

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	std::thread st([&serializer]()
	{
		serializer.test_run();
	});

	// Wait for the CM to connect
	uint32_t loops = 0;
	while(fc.get_num_connects() < 1 && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());
	ASSERT_EQ(1, fc.get_num_connects());

	// Now send an INVALID CUSTOMER KEY error
	draiosproto::error_message err;
	err.set_type(draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY);
	err.set_description("CM UNIT TEST");

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                     dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                     err);
	ASSERT_TRUE(ret);

	// Ensure the CM drops the connection
	for(uint32_t loops = 0; fc.get_num_disconnects() < 1 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	// The backoff should now be 1
	ASSERT_EQ(1, cm.get_reconnect_interval());

	// Wait for the CM to connect again
	loops = 0;
	while(fc.get_num_connects() < 2 && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());
	ASSERT_EQ(2, fc.get_num_connects());

	// Send some metrics
	{
		auto metrics = build_test_metrics(1);
		serializer.serialize(std::make_shared<flush_data_message>(
		                         sinsp_utils::get_current_time_ns(),
		                         &metrics_sent,
		                         std::unique_ptr<draiosproto::metrics>(metrics),
		                         MAX_QUEUE_LEN,
		                         0,
		                         1.0,
		                         1,
		                         0));
	}

	// Now send the INVALID CUSTOMER KEY error again
	err.set_type(draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY);
	err.set_description("CM UNIT TEST");
	ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                dragent_protocol::PROTOCOL_VERSION_NUMBER,
	                                err);
	ASSERT_TRUE(ret);

	// Ensure the CM drops the connection yet again
	for(uint32_t loops = 0; fc.get_num_disconnects() < 2 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(2, fc.get_num_disconnects());
	// The backoff should now be 2
	ASSERT_EQ(2, cm.get_reconnect_interval());


	// Wait for the CM to connect again
	loops = 0;
	while(fc.get_num_connects() < 3 && loops < 21000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());
	ASSERT_EQ(3, fc.get_num_connects());

	uint32_t index = 2;
	// Build and send metrics until the backoff goes back to 1
	for(uint32_t loops = 0; cm.get_reconnect_interval() > 1 && loops < 15; ++loops)
	{
		auto metrics = build_test_metrics(index++);
		serializer.serialize(std::make_shared<flush_data_message>(
		                         sinsp_utils::get_current_time_ns(),
		                         &metrics_sent,
		                         std::unique_ptr<draiosproto::metrics>(metrics),
		                         MAX_QUEUE_LEN,
		                         0,
		                         1.0,
		                         1,
		                         0));
		usleep(200000); // 200 ms
	}

	ASSERT_EQ(0, cm.get_reconnect_interval());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
	serializer.stop();
	st.join();
}

////////////////////////////////////////////////////////////
// HTTP Proxy tests
////////////////////////////////////////////////////////////

struct http_context
{
	struct credentials
	{
		std::string user;
		std::string password;
	};

	bool big_resp;
	bool validate_credentials;
	std::vector<credentials> creds;
	std::string host;
	uint32_t good_requests;
	uint32_t bad_requests;
	uint32_t auth_mismatches;

	static http_context build_default()
	{
		return http_context
		{
			false,
			false,
			{},
			"sysdig.com:1234"
		};
	}
};

///
/// Handles and validates proxy CONNECT requests
///
class HTTPProxyHandler : public Poco::Net::HTTPRequestHandler
{
public:
	HTTPProxyHandler(http_context* context) : m_ctxt(context) {}

	// Build a string with random chars just to pad space
	std::string get_random_string(uint32_t length)
	{
		std::stringstream ss;
		char c;

		for (uint32_t i = 0; i < length; ++i)
		{
			c = 'A' + (rand() % ('z' - 'A'));
			ss << c;
		}
		return ss.str();
	}

	virtual void handleRequest(Poco::Net::HTTPServerRequest& request,
	                           Poco::Net::HTTPServerResponse& response) override
	{
		// Validate the request
		if (request.getMethod() != Poco::Net::HTTPRequest::HTTP_CONNECT)
		{
			std::cerr << "Mismatch: " << request.getMethod()
			          << " != " << Poco::Net::HTTPRequest::HTTP_CONNECT
			          << std::endl;
			++m_ctxt->bad_requests;
			return;
		}
		if (request.getHost() != m_ctxt->host)
		{
			std::cerr << "Mismatch: " << request.getHost()
			          << " != " << m_ctxt->host << std::endl;
			++m_ctxt->bad_requests;
			return;
		}

		// Optionally validate authentication credentials
		if (m_ctxt->validate_credentials)
		{
			std::string scheme, auth;
			bool found = false;

			try
			{
				request.getProxyCredentials(scheme, auth);
				for (auto c : m_ctxt->creds)
				{
					std::string result = http_tunnel::encode_auth(c.user, c.password);
					if (auth == result)
					{
						found = true;
						break;
					}
				}
			}
			catch (Poco::Net::NotAuthenticatedException& ex)
			{
				// No credentials specified but credentials expected
				found = false;
			}

			// Credentials matched
			if (found)
			{
				++m_ctxt->good_requests;
				response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
			}
			else // Mismatch
			{
				++m_ctxt->auth_mismatches;
				response.setStatus(Poco::Net::HTTPResponse::HTTP_PROXY_AUTHENTICATION_REQUIRED);
			}
		}
		else // Not validating credentials, just return good response
		{
			response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
			++m_ctxt->good_requests;
		}

		response.setContentType("text/html");

		if (m_ctxt->big_resp)
		{
			response.set("x-application-garbage-data", get_random_string(1024));
		}

		std::ostream& out = response.send();
		out << "<html><body>"
		    << "<h1>Sysdig agent proxy test test</h1>"
		    << "<p>Request host = " << request.getHost() << "</p>"
		    << "<p>Request URI = " << request.getURI() << "</p>"
		    << "</body></html>" << std::flush;
	}

private:
	http_context* m_ctxt;
};

///
/// Sample request handler factory for a trivial HTTP request handler
///
class HTTPPHFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
	HTTPPHFactory(http_context* context) : m_ctxt(context) {}

	virtual Poco::Net::HTTPRequestHandler* createRequestHandler(
	        const Poco::Net::HTTPServerRequest&) override
	{
		return new HTTPProxyHandler(m_ctxt);
	}

private:
	http_context* m_ctxt;
};

TEST_F(connection_manager_fixture, incomplete_resp)
{
	std::string str = "";

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str.append("General nonsense");

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str.append("\r\n");

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str.append("Specific nonsense \r with embedded nonsense \n\r\n");

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str.append("Bogosity without end \r\n \r\n");

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str.append("\n\r\n\n\n\n\r\n");

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));
}

TEST_F(connection_manager_fixture, complete_resp)
{
	std::string str;

	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str = "General nonsense\r\n"
	      "Thing: other thing\r\n"
	      "Foo: Bar\r\n";
	ASSERT_FALSE(http_tunnel::is_resp_complete(str));

	str.append("\r\n");

	ASSERT_TRUE(http_tunnel::is_resp_complete(str));

	str = "\r\n\r\n";

	ASSERT_TRUE(http_tunnel::is_resp_complete(str));
}

TEST_F(connection_manager_fixture, parse_resp)
{
	std::string resp;
	http_tunnel::http_response rcode;

	// 1. Standard success response (taken from an actual proxy)
	resp = "HTTP/1.1 200 Connection established\r\n\r\n";
	rcode = http_tunnel::parse_resp(resp);
	ASSERT_TRUE(rcode.is_valid);
	ASSERT_EQ(200, rcode.resp_code);

	// 2. Standard failure response (taken from an actual proxy)
	// Note: this string is truncated at 1024 bytes as it would
	//       be in the actual http tunnel.
	resp = "HTTP/1.1 503 Service Unavailable\r\n"
	       "Server: squid/3.5.12\r\n"
	       "Mime-Version: 1.0\r\n"
	       "Date: Fri, 03 Apr 2020 10:30:33 GMT\r\n"
	       "Content-Type: text/html;charset=utf-8\r\n"
	       "Content-Length: 3613\r\n"
	       "X-Squid-Error: ERR_CONNECT_FAIL 111\r\n"
	       "Vary: Accept-Language\r\n"
	       "Content-Language: en\r\n"
	       "\r\n\r\n"
	       "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" "
	       "\"http://www.w3.org/TR/html4/strict.dtd\">\r\n"
	       "<html><head>\r\n"
	       "<meta type=\"copyright\" "
	       "content=\"Copyright (C) 1996-2015 The Squid Software Foundation and contributors\">\r\n"
	       "<meta http-equiv=\"Content-Type\" CONTENT=\"text/html; charset=utf-8\">\r\n"
	       "<title>ERROR: The requested URL could not be retrieved</title>\r\n"
	       "<style type=\"text/css\"><!-- \r\n"
	       " /*\r\n"
	       " * Copyright (C) 1996-2015 The Squid Software Foundation and contributors\r\n"
	       " * \r\n"
	       " * Squid software is distributed under GPLv2+ license and includes\r\n"
	       "\r\n * contributions from numerous individuals and organizations."
	       " * Please see the COPYING and CONTRIBUTORS files for details.\r\n"
	       " */\r\n"
	       "\r\n"
	       "/*\r\n"
	       " Stylesheet for Squid Error pages\r\n"
	       " Adapted from design by Free CSS Templates\r\n"
	       " http://www.freecsstemplates.org\r\n"
	       " Release\r\n";
	rcode = http_tunnel::parse_resp(resp);
	ASSERT_TRUE(rcode.is_valid);
	ASSERT_EQ(503, rcode.resp_code);

	// 3. Empty string
	resp = "";
	rcode = http_tunnel::parse_resp(resp);
	ASSERT_FALSE(rcode.is_valid);

	// 4. Garbage string
	resp = "Who are you calling garbage, mister?";
	rcode = http_tunnel::parse_resp(resp);
	ASSERT_FALSE(rcode.is_valid);
}

TEST_F(connection_manager_fixture, basic_proxy_connect)
{
	http_context ctxt = http_context::build_default();
	scoped_http_server srv(9090, new HTTPPHFactory(&ctxt));

	try
	{
		auto ret = http_tunnel::establish_tunnel({"127.0.0.1", 9090, "sysdig.com", 1234});
		ASSERT_NE(nullptr, ret);
	}
	catch (Poco::Exception& ex)
	{
		std::cerr << "Poco exception " << ex.displayText() << std::endl;
	}

	ASSERT_EQ(1, ctxt.good_requests);
	ASSERT_EQ(0, ctxt.bad_requests);
}

TEST_F(connection_manager_fixture, proxy_connect_big_resp)
{
	http_context ctxt = http_context::build_default();
	ctxt.big_resp = true;
	scoped_http_server srv(9090, new HTTPPHFactory(&ctxt));

	try
	{
		auto ret = http_tunnel::establish_tunnel({"127.0.0.1", 9090, "sysdig.com", 1234});
		ASSERT_NE(nullptr, ret);
	}
	catch (Poco::Exception& ex)
	{
		std::cerr << "Poco exception " << ex.displayText() << std::endl;
	}

	ASSERT_EQ(1, ctxt.good_requests);
	ASSERT_EQ(0, ctxt.bad_requests);
}

TEST_F(connection_manager_fixture, proxy_connect_auth)
{
	http_context::credentials creds {"sysdig", "password"};
	http_context ctxt = http_context::build_default();
	ctxt.validate_credentials = true;
	ctxt.creds.push_back(creds);
	scoped_http_server srv(9090, new HTTPPHFactory(&ctxt));

	try
	{
		auto ret = http_tunnel::establish_tunnel({"127.0.0.1",
		                                         9090,
		                                         "sysdig.com",
		                                         1234,
		                                         creds.user,
		                                         creds.password});
		ASSERT_NE(nullptr, ret);
	}
	catch (Poco::Exception& ex)
	{
		std::cerr << "Poco exception " << ex.displayText() << std::endl;
	}

	ASSERT_EQ(1, ctxt.good_requests);
	ASSERT_EQ(0, ctxt.bad_requests);
	ASSERT_EQ(0, ctxt.auth_mismatches);
}

TEST_F(connection_manager_fixture, proxy_auth_failure)
{
	http_context::credentials creds {"sysdig", "password"};
	http_context ctxt = http_context::build_default();
	ctxt.validate_credentials = true;
	ctxt.creds.push_back(creds);
	scoped_http_server srv(9090, new HTTPPHFactory(&ctxt));

	try
	{
		std::string badpass = "barf";
		auto ret = http_tunnel::establish_tunnel({"127.0.0.1",
		                                         9090,
		                                         "sysdig.com",
		                                         1234,
		                                         creds.user,
		                                         "barf"});
		ASSERT_EQ(nullptr, ret);
	}
	catch (Poco::Exception& ex)
	{
		std::cerr << "Poco exception " << ex.displayText() << std::endl;
	}

	ASSERT_EQ(0, ctxt.good_requests);
	ASSERT_EQ(0, ctxt.bad_requests);
	ASSERT_EQ(1, ctxt.auth_mismatches);
}

TEST_F(connection_manager_fixture, encode_auth)
{
	struct pw_entry
	{
		std::string username;
		std::string password;
		std::string encode;
	};
	// I got these values from the base64 program that ships with my distro
	std::vector<pw_entry> auth_list
	{
		{"sysdig", "sysdig", "c3lzZGlnOnN5c2RpZw=="},
		{"sysdig", "sysdig1!", "c3lzZGlnOnN5c2RpZzEh"},
		{"a",      "b",   "YTpi"},
		{"1", "2", "MToy"},
		{"testusernamethatsabitlongerthantheusualones", "password", "dGVzdHVzZXJuYW1ldGhhdHNhYml0bG9uZ2VydGhhbnRoZXVzdWFsb25lczpwYXNzd29yZA=="},
		{"username", "testpasswordthatsabitlongerthantheusualones", "dXNlcm5hbWU6dGVzdHBhc3N3b3JkdGhhdHNhYml0bG9uZ2VydGhhbnRoZXVzdWFsb25lcw=="},
		{"username", "pass:word", "dXNlcm5hbWU6cGFzczp3b3Jk"},
		{"username", "", "dXNlcm5hbWU6"},
		{"username", "!@#$%^&*()asdf<>?:\";'[]{}\\|", "dXNlcm5hbWU6IUAjJCVeJiooKWFzZGY8Pj86IjsnW117fVx8"},
	};

	for (auto entry : auth_list)
	{
		std::string result = http_tunnel::encode_auth(entry.username, entry.password);
		ASSERT_EQ(entry.encode, result);
	}
}

void fill_buf_with_random(char* buf, uint32_t length)
{
	char c;

	for (uint32_t i = 0; i < length; ++i)
	{
		c = 'A' + (rand() % ('z' - 'A'));
		buf[i] = c;
	}
}

TEST_F(connection_manager_fixture, string_append_test)
{
	char buf1[32];
	char buf2[16];

	fill_buf_with_random(buf1, sizeof(buf1));
	fill_buf_with_random(buf2, sizeof(buf2));

	std::string result;

	result.append(buf1, sizeof(buf1));
	result.append(buf2, sizeof(buf2));

	ASSERT_EQ(sizeof(buf1) + sizeof(buf2), result.length());

	for (uint32_t i = 0; i < sizeof(buf1); ++i)
	{
		ASSERT_EQ(buf1[i], result[i]);
	}

	for (uint32_t i = 0; i < sizeof(buf2); ++i)
	{
		ASSERT_EQ(buf2[i], result[sizeof(buf1) + i]);
	}
}

//
// End HTTP proxy tests
//


// I wrote this test to make sure the index value gets propagated through
TEST_F(connection_manager_fixture, aggregator_integration_test)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();
	std::atomic<bool> metrics_sent(false);

	// Create the shared blocking queues
	flush_queue fqueue(MAX_QUEUE_LEN);
	protocol_queue pqueue(MAX_QUEUE_LEN);
	dragent::async_aggregator::queue_t input(MAX_QUEUE_LEN);

	// All the stuff to build a serializer
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<bogus_capture_stats_source>();
	protocol_handler ph(pqueue);
	auto compressor = gzip_protobuf_compressor::get(-1);

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);

	ASSERT_GT(fc.get_port(), 0);

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create and spin up the bits
	connection_manager cm(&config, &pqueue, {5});
	protobuf_metric_serializer serializer(stats_source,
	                                      "",
	                                      ph,
	                                      &fqueue,
	                                      &pqueue,
	                                      compressor,
	                                      &cm);
	dragent::async_aggregator aggregator(input,
	                                     fqueue,
	                                     1,
	                                     1,
	                                     "");
	watchdog_runnable_pool pool;
	std::thread ct([&cm]()
	{
		cm.test_run();
	});

	std::thread st([&serializer]()
	{
		serializer.test_run();
	});

	pool.start(aggregator, 10);

	// Build the test data
	std::list<draiosproto::metrics> test_data;
	for (uint32_t i = 0; i < MAX_QUEUE_LEN; ++i)
	{
		draiosproto::metrics* m = build_test_metrics(i + 1);
		m->set_timestamp_ns(sinsp_utils::get_current_time_ns());
		test_data.push_back(*m);  // save for comparison
		input.put(std::make_shared<flush_data_message>(
		                         sinsp_utils::get_current_time_ns(),
		                         &metrics_sent,
		                         std::unique_ptr<draiosproto::metrics>(m),
		                         MAX_QUEUE_LEN,
		                         0,
		                         1.0,
		                         1,
		                         0));

		// Make sure each message gets sent before processing the next
		for (uint32_t i = 0; cm.get_sequence() <= i && i < 5000; ++i)
		{
			msleep(100);
		}
	}

	// wait for all the messages to be processed
	for (uint32_t i = 0; cm.get_sequence() <= MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(cm.get_sequence(), MAX_QUEUE_LEN + 1);

	// Pop the handshake messages off the data queue
	ASSERT_GT(fc.has_data(), 2);
	(void)fc.pop_data();
	(void)fc.pop_data();

	// wait for all the data to be received
	for (uint32_t i = 0; fc.has_data() < MAX_QUEUE_LEN && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), MAX_QUEUE_LEN);
	ASSERT_EQ(0, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	ct.join();
	serializer.stop();
	st.join();
	aggregator.stop();
	pool.stop_all();

	// Validate the messages received by the fake collector
	uint64_t idx = 1;
	for (auto sent_data : test_data)
	{
		ASSERT_TRUE(fc.has_data());
		fake_collector::buf b = fc.pop_data();

		draiosproto::metrics received_metrics;
		dragent_protocol::buffer_to_protobuf(b.ptr,
		                                     b.payload_len,
		                                     &received_metrics,
		                                     protocol_compression_method::GZIP);

		EXPECT_EQ(sent_data.timestamp_ns(), received_metrics.timestamp_ns());
		EXPECT_EQ(sent_data.customer_id(), received_metrics.customer_id());
		EXPECT_EQ(sent_data.machine_id(), received_metrics.machine_id());
		EXPECT_EQ(sent_data.index(), received_metrics.index());
		EXPECT_EQ(idx, received_metrics.index());
		++idx;
	}
}

TEST_F(connection_manager_fixture, test_error_message_invalid_version)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();

	// Create and spin up the fake collector (get an ephemeral port)
	fake_collector fc(true);
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	const std::string token = "B17EFACE";
	auto mh = std::make_shared<counting_message_handler>(token);
	connection_manager cm(&config,
	                      &queue,
	                      {5},
	                      {{draiosproto::message_type::DUMP_REQUEST_START, mh}});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	// Wait for the connection to be established
	uint32_t loops = 0;
	while(cm.get_state() != cm_state_machine::state::STEADY_STATE && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(cm_state_machine::state::STEADY_STATE, cm.get_state());
	ASSERT_EQ(0, cm.m_num_invalid_messages);

	// Build a collector message
	draiosproto::error_message err;
	err.set_type(draiosproto::error_type::ERR_SERVER_BUSY);

	// Send the message
	bool ret = fc.send_collector_message(draiosproto::message_type::ERROR_MESSAGE,
	                                     2,
	                                     err);

	ASSERT_TRUE(ret);

	loops = 0;
	while (cm.m_num_invalid_messages == 0 && loops < 10000)
	{
		usleep(1000);
		++loops;
	}
	ASSERT_EQ(1, cm.m_num_invalid_messages);
	ASSERT_EQ(2, fc.has_data());

	// Make sure the agent can still send and receive messages OK
	auto buf = std::make_shared<serialized_buffer>();
	buf->ts_ns = sinsp_utils::get_current_time_ns();
	buf->message_type = draiosproto::message_type::METRICS;
	buf->buffer = build_test_string(32);
	queue.put(buf, protocol_queue::BQ_PRIORITY_HIGH);

	for (uint32_t i = 0; fc.has_data() == 2 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(fc.has_data(), 3);

	// Build and send a collector message
	draiosproto::dump_request_start dump_start;
	dump_start.set_timestamp_ns(sinsp_utils::get_current_time_ns());
	dump_start.set_machine_id("0");
	dump_start.set_token(token);
	ret = fc.send_collector_message(draiosproto::message_type::DUMP_REQUEST_START,
	                                5,
	                                dump_start);
	ASSERT_TRUE(ret);
	for (uint32_t i = 0; mh->num_received() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, mh->num_received());
	ASSERT_FALSE(mh->has_token_mismatch());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();
	t.join();
}

TEST_F(connection_manager_fixture, handshake_timeout)
{
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	dragent_configuration config;
	config.init();
	test_helpers::scoped_config<uint32_t> conn_timeout("connect_timeout", 1500);

	// Create and spin up the fake collector
	fake_collector fc(false); // Don't auto respond
	fc.start(0);
	ASSERT_NE(0, fc.get_port());

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = fc.get_port();
	config.m_ssl_enabled = false;

	// Create the shared blocking queue
	protocol_queue queue(MAX_QUEUE_LEN);

	// Create and spin up the connection manager
	connection_manager cm(&config, &queue, {5});

	std::thread t([&cm]()
	{
		cm.test_run();
	});

	for(uint32_t loops = 0; fc.has_data() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(fc.has_data(), 1);

	// Should have gotten a PROTOCOL_INIT message
	fake_collector::buf b = fc.pop_data();
	ASSERT_EQ(draiosproto::message_type::PROTOCOL_INIT, b.hdr.v4.messagetype);

	// Validate the protocol_init message
	draiosproto::protocol_init pi;
	dragent_protocol::buffer_to_protobuf(b.ptr,
	                                     b.payload_len,
	                                     &pi,
	                                     protocol_compression_method::NONE);

	ASSERT_EQ(1, pi.supported_protocol_versions().size());
	dragent_protocol::protocol_version version = pi.supported_protocol_versions()[0];
	ASSERT_EQ(dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH, version);

	// Wait for timeout
	for(uint32_t loops = 0; fc.get_num_disconnects() == 0 && loops < 2000; ++loops)
	{
		usleep(1000);
	}

	ASSERT_EQ(1, fc.get_num_disconnects());

	// Shut down all the things
	running_state::instance().shut_down();
	fc.stop();

	t.join();
}
