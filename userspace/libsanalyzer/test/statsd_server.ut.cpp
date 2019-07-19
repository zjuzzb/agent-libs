/**
 * @file
 *
 * Unit test for statd_server.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_fault.h"
#include "statsd_server.h"
#include "statsd_stats_destination.h"
#include <algorithm>
#include <cstdio>
#include <chrono>
#include <fstream>
#include <gtest.h>
#include <mutex>
#include <thread>
#include <vector>
#include <Poco/Thread.h>
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/SocketReactor.h>

/**
 * Print a message to stdout in a gtest-like format since gtest doesn't seem
 * to have a trace message facility.
 */
#define TRACE_MSG(fmt, ...)                                      \
	do                                                       \
        {                                                        \
        	printf("%s[   INFO   ]%s " fmt "\n",             \
        	       "\033[0;32m",                             \
        	       "\033[0;0m",                              \
        	       ##__VA_ARGS__);                           \
        	fflush(stdout);                                  \
	}                                                        \
	while(false)

using test_helpers::scoped_fault;
using userspace_shared::fault_handler;

namespace
{

/**
 * A dummy realization of the statsd_stats_destination that simply saves
 * the metrics that it receives in the order in which they are received.
 */
class dummy_statsd_statsd_destination : public statsd_stats_destination
{
public:
	using id_content_pair = std::pair<std::string, std::string>;

	/**
	 * Send one or more statsd metrics for the host.
	 */
	void send_metric(const char* const data, const uint64_t len) override
	{
		std::unique_lock<std::mutex> guard(m_mutex);

		m_content.push_back(std::make_pair("", std::string(data, len)));
	}

	/**
	 * Send one or more statsd metrics for the given container_id.
	 */
	void send_container_metric(const std::string& container_id,
	                           const char* const data,
	                           const uint64_t len) override
	{
		std::unique_lock<std::mutex> guard(m_mutex);

		m_content.push_back(std::make_pair(container_id,
		                                   std::string(data, len)));
	}

	/**
	 * Returns the number of received metrics.
	 */
	size_t get_content_size() const
	{
		std::unique_lock<std::mutex> guard(m_mutex);

		return m_content.size();
	}

	/**
	 * Returns the received id/metic pair at the given index.
	 *
	 * Precondition: index < get_content_size()
	 */
	id_content_pair get_content_at(const int index)
	{
		std::unique_lock<std::mutex> guard(m_mutex);

		return m_content[index];
	}

private:
	using content_list = std::vector<id_content_pair>;

	content_list m_content;
	mutable std::mutex m_mutex;
};

/**
 * Send an UDP datagram via IPv4 to a statsd_server on the loopback interface.
 *
 * If the statsd_server cannot create an IPv4 datagram socket endpoint,
 * then we skip this test.
 *
 * @param[in] size                     The number of bytes to send.
 * @param[in] expected_buffer_capacity The expected size of the statsd_server%'s
 *                                     buffer after it receives the message.
 */
void ipv4_send(const size_t size, const size_t expected_buffer_capacity)
{
	using Poco::Net::SocketAddress;

	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	if(server.get_ipv4_socket() == nullptr)
	{
		TRACE_MSG("Skipping test -- no IPv4 socket available");
		return;
	}

	Poco::Thread reactor_thread;
	reactor_thread.start(reactor);

	std::vector<char> message(size);
	std::fill(message.begin(), message.end(), 'X');

	Poco::Net::DatagramSocket send_socket;

	const bool reuse_address = true;
	send_socket.bind(SocketAddress("127.0.0.1", 0), reuse_address);

	ASSERT_EQ(message.size(),
	          send_socket.sendTo(message.data(),
		                     message.size(),
			             SocketAddress("127.0.0.1",
			                           server.get_ipv4_port())));

	// Wait for the message to be received and processed.  If we have to
	// wait more than 5 seconds, something has gone badly wrong.
        const int FIVE_SECOND_IN_MS = 5 * 1000;
        for(int i = 0; (dest.get_content_size() != 2) && (i < FIVE_SECOND_IN_MS); ++i)
        {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
	reactor.stop();
	reactor_thread.join();

	// Should have received two callbacks, one for the container and one
	// for the host
	ASSERT_EQ(2, dest.get_content_size());

	const std::string expected(message.data(), message.size());

	// First container_id should be the container id (for the container).
	ASSERT_EQ(containerid, dest.get_content_at(0).first);
	ASSERT_EQ(expected, dest.get_content_at(0).second);

	// Second container_id should be "" (for the host).
	ASSERT_EQ("", dest.get_content_at(1).first);
	ASSERT_EQ(expected, dest.get_content_at(1).second);

	// Make sure the resulting data buffer has the expected capacity
	ASSERT_EQ(expected_buffer_capacity, server.get_data_buffer_capacity());
}

/**
 * Send an UDP datagram via IPv6 to a statsd_server on the loopback interface.
 *
 * If the statsd_server cannot create an IPv6 datagram socket endpoint,
 * then we skip this test.
 *
 * @param[in] size                     The number of bytes to send.
 * @param[in] expected_buffer_capacity The expected size of the statsd_server%'s
 *                                     buffer after it receives the message.
 */
void ipv6_send(const size_t size, const size_t expected_buffer_capacity)
{
	using Poco::Net::SocketAddress;

	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	if(server.get_ipv6_socket() == nullptr)
	{
		TRACE_MSG("Skipping test -- no IPv6 socket available");
		return;
	}

	Poco::Thread reactor_thread;
	reactor_thread.start(reactor);

	std::vector<char> message(size);
	std::fill(message.begin(), message.end(), 'X');

	Poco::Net::DatagramSocket send_socket;

	const bool reuse_address = true;
	send_socket.bind(SocketAddress("::1", 0), reuse_address);

	ASSERT_EQ(message.size(),
	          send_socket.sendTo(message.data(),
		                     message.size(),
			             SocketAddress("::1",
			                           server.get_ipv6_port())));

	// Wait for the message to be received and processed.  If we have to
	// wait more than 5 seconds, something has gone badly wrong.
        const int FIVE_SECOND_IN_MS = 5 * 1000;
        for(int i = 0; (dest.get_content_size() != 2) && (i < FIVE_SECOND_IN_MS); ++i)
        {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
	reactor.stop();
	reactor_thread.join();

	// Should have received two callbacks, one for the container and one
	// for the host
	ASSERT_EQ(2, dest.get_content_size());

	const std::string expected(message.data(), message.size());

	// First container_id should be the container id (for the container).
	ASSERT_EQ(containerid, dest.get_content_at(0).first);
	ASSERT_EQ(expected, dest.get_content_at(0).second);

	// Second container_id should be "" (for the host).
	ASSERT_EQ("", dest.get_content_at(1).first);
	ASSERT_EQ(expected, dest.get_content_at(1).second);

	// Make sure the resulting data buffer has the expected capacity
	ASSERT_EQ(expected_buffer_capacity, server.get_data_buffer_capacity());
}

/**
 * Look up the MTU of the loopback interface by querying sysfs.
 * Otherwise, we don't have a good way to know what the MTU of the
 * interface is.  If we can't read the file, we'll skip this test.
 */
bool get_mtu(size_t& mtu)
{
	// Cache the value; we don't expect the value to change over the
	// lifetime of the test binary.
	static size_t last_mtu = 0;

	if(last_mtu == 0)
	{
		std::ifstream in("/sys/class/net/lo/mtu");

		if(in)
		{
			in >> last_mtu;
		}
		else
		{
			return false;
		}
	}

	mtu = last_mtu;

	return true;
}

} // end namespace

/**
 * Ensure that if a statsd_server successfully creates an IPv4 socket on
 * construction, that that socket and the corresponding read observer are
 * registered with the SocketReactor.
 *
 * If the statsd_server cannot create an IPv4 datagram socket endpoint,
 * then we skip this test.
 */
TEST(statsd_server_test, initial_state_ipv4_socket_read_observer_registered_with_reactor)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	if(server.get_ipv4_socket() == nullptr)
	{
		TRACE_MSG("Skipping test -- no IPv4 socket available");
		return;
	}

	ASSERT_TRUE(reactor.hasEventHandler(*server.get_ipv4_socket(),
					    server.get_read_observer()));
}

/**
 * Ensure that if a statsd_server successfully creates an IPv4 socket on
 * construction, that that socket and the corresponding error observer are
 * registered with the SocketReactor.
 *
 * If the statsd_server cannot create an IPv4 datagram socket endpoint,
 * then we skip this test.
 */
TEST(statsd_server_test, initial_state_ipv4_socket_error_observer_registered_with_reactor)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	if(server.get_ipv4_socket() == nullptr)
	{
		TRACE_MSG("Skipping test -- no IPv4 socket available");
		return;
	}

	ASSERT_TRUE(reactor.hasEventHandler(*server.get_ipv4_socket(),
					    server.get_error_observer()));
}

/**
 * Ensure that if a statsd_server successfully creates an IPv6 socket on
 * construction, that that socket and the corresponding read observer are
 * registered with the SocketReactor.
 *
 * If the statsd_server cannot create an IPv6 datagram socket endpoint,
 * then we skip this test.
 */
TEST(statsd_server_test, initial_state_ipv6_socket_read_observer_registered_with_reactor)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	if(server.get_ipv6_socket() == nullptr)
	{
		TRACE_MSG("Skipping test -- no IPv6 socket available");
		return;
	}

	ASSERT_TRUE(reactor.hasEventHandler(*server.get_ipv6_socket(),
					    server.get_read_observer()));
}

/**
 * Ensure that if a statsd_server successfully creates an IPv6 socket on
 * construction, that that socket and the corresponding error observer are
 * registered with the SocketReactor.
 *
 * If the statsd_server cannot create an IPv6 datagram socket endpoint,
 * then we skip this test.
 */
TEST(statsd_server_test, initial_state_ipv6_socket_error_observer_registered_with_reactor)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	if(server.get_ipv6_socket() == nullptr)
	{
		TRACE_MSG("Skipping test -- no IPv6 socket available");
		return;
	}

	ASSERT_TRUE(reactor.hasEventHandler(*server.get_ipv6_socket(),
					    server.get_error_observer()));
}

/**
 * Ensure that a newly-created statsd_server has the correct container_id.
 */
TEST(statsd_server_test, initial_state_container_id)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(containerid, server.get_container_id());
}

/**
 * Ensure that if a statsd_server successfully creates an IPv4 socket on
 * construction, and that if the given port was 0, that the implementation
 * picks an ephemeral port.  If the server cannot create an IPv4 socket,
 * the port should be 0.
 */
TEST(statsd_server_test, initial_state_ipv4_port_correct)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(containerid, server.get_container_id());

	if(server.get_ipv4_socket() != nullptr)
	{
		ASSERT_NE(0, server.get_ipv4_port());
	}
}

/**
 * Ensure that if a statsd_server successfully creates an IPv6 socket on
 * construction, and that if the given port was 0, that the implementation
 * picks an ephemeral port.  If the server cannot create an IPv4 socket,
 * the port should be 0.
 */
TEST(statsd_server_test, initial_state_ipv6_port_correct)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(containerid, server.get_container_id());

	if(server.get_ipv6_socket() != nullptr)
	{
		ASSERT_NE(0, server.get_ipv6_port());
	}
}

/**
 * Ensure that the data buffer capacity of a statsd_server is the expected
 * value on creation.
 */
TEST(statsd_server_test, initial_state_data_buffer_capacity)
{
	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(statsd_server::INITIAL_READ_SIZE, server.get_data_buffer_capacity());
}

/**
 * Send INITIAL_READ_SIZE bytes to a statsd_server%'s IPv4 socket and make sure
 * that the statd_server reads those bytes.
 */
TEST(statsd_server_test, send_initial_buffer_size_bytes_ipv4)
{
	ipv4_send(statsd_server::INITIAL_READ_SIZE,
	          statsd_server::INITIAL_READ_SIZE);
}

/**
 * Send the maximum number of bytes the loopback interface can handle to a
 * statsd_server%'s IPv4 socket and make sure that the statsd_server reads
 * those bytes.
 *
 * If we cannot read /sys/class/net/lo/mtu, then we skip this test.
 */
TEST(statsd_server_test, send_max_buffer_size_bytes_ipv4)
{
	size_t mtu = 0;

	if(get_mtu(mtu))
	{
		ASSERT_NE(0, mtu);

		// Subtract 32 bytes to account for the various protocol headers
		ipv4_send(mtu - 32, (mtu - 32) * statsd_server::RESIZE_SCALE_FACTOR);
	}
	else
	{
		TRACE_MSG("Unable to open '/sys/class/net/lo/mtu' -- skipping test");
	}
}

/**
 * Send INITIAL_READ_SIZE bytes to a statsd_server%'s IPv6 socket and make sure
 * that the statd_server reads those bytes.
 */
TEST(statsd_server_test, send_initial_buffer_size_bytes_ipv6)
{
	ipv6_send(statsd_server::INITIAL_READ_SIZE,
	          statsd_server::INITIAL_READ_SIZE);
}

/**
 * Send the maximum number of bytes the loopback interface can handle to a
 * statsd_server%'s IPv6 socket and make sure that the statsd_server reads
 * those bytes.
 *
 * If we cannot read /sys/class/net/lo/mtu, then we skip this test.
 */
TEST(statsd_server_test, send_max_buffer_size_bytes_ipv6)
{
	size_t mtu = 0;

	if(get_mtu(mtu))
	{
		ASSERT_NE(0, mtu);

		// Subtract 40 bytes to account for the various protocol headers
		ipv6_send(mtu - 40, (mtu - 40) * statsd_server::RESIZE_SCALE_FACTOR);
	}
	else
	{
		TRACE_MSG("Unable to open '/sys/class/net/lo/mtu' -- skipping test");
	}
}

/**
 * Ensure that if the attempt to create the IPv4 socket fails,
 * that get_ipv4_socket() returns nullptr.
 */
TEST(statsd_server_test, get_ipv4_socket_returns_nullptr_if_socket_creation_fails)
{
	scoped_fault fault("agent.userspace.libsanalyzer.statsd_server.no_ipv4_socket");

	fault.handler()->set_enabled(true);
	fault.handler()->set_fault_mode(fault_handler::fault_mode::ALWAYS);

	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(nullptr, server.get_ipv4_socket());
}

/**
 * Ensure that if the attempt to create the IPv6 socket fails,
 * that get_ipv6_socket() returns nullptr.
 */
TEST(statsd_server_test, get_ipv6_socket_returns_nullptr_if_socket_creation_fails)
{
	scoped_fault fault("agent.userspace.libsanalyzer.statsd_server.no_ipv6_socket");

	fault.handler()->set_enabled(true);
	fault.handler()->set_fault_mode(fault_handler::fault_mode::ALWAYS);

	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(nullptr, server.get_ipv6_socket());
}

/**
 * Ensure that if the attempt to create the IPv4 socket fails,
 * that get_ipv4_port() returns 0.
 */
TEST(statsd_server_test, get_ipv4_port_returns_zero_if_socket_creation_fails)
{
	scoped_fault fault("agent.userspace.libsanalyzer.statsd_server.no_ipv4_socket");

	fault.handler()->set_enabled(true);
	fault.handler()->set_fault_mode(fault_handler::fault_mode::ALWAYS);

	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(0, server.get_ipv4_port());
}

/**
 * Ensure that if the attempt to create the IPv6 socket fails,
 * that get_ipv6_port() returns 0.
 */
TEST(statsd_server_test, get_ipv6_port_returns_0_if_socket_creation_fails)
{
	scoped_fault fault("agent.userspace.libsanalyzer.statsd_server.no_ipv6_socket");

	fault.handler()->set_enabled(true);
	fault.handler()->set_fault_mode(fault_handler::fault_mode::ALWAYS);

	Poco::Net::SocketReactor reactor;
	const std::string containerid = "123456789abc";
	dummy_statsd_statsd_destination dest;

	statsd_server server(containerid, dest, reactor, 0);

	ASSERT_EQ(0, server.get_ipv6_port());
}
