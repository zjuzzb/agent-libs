/**
 * @file
 *
 * Interface to statsd_server.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <Poco/Observer.h>

class statsd_stats_destination;

namespace Poco {
namespace Net {

class DatagramSocket;
class SocketAddress;
class ErrorNotification;
class ReadableNotification;
class SocketReactor;

} // namespace Net
} // namespace Poco

/**
 * A statsd_server attempts to bind to localhost (both IPv4 and IPv6) on the
 * specified port and reads any statsd messages received from those
 * sockets.  Any statsd messages that are read are forwarded to the given
 * proxy.
 */
class statsd_server
{
public:
	/**
	 * Initializes this statsd_server by attempting to create IPv4 and
	 * IPv6 UDP sockets on localhost:port.
	 *
	 * @param[in] containerid The ID of the container from which this
	 *                        statsd_server will receive messages.
	 * @param[in] proxy       The destination to which to forward any
	 *                        received messages.
	 * @param[in] reactor     The object that reacts to socket events
	 *                        by informing this statsd_server that the
	 *                        event has occurred.
	 * @param[in] port        The UDP port on which to listen.
	 */
	statsd_server(const std::string& containerid,
	              statsd_stats_destination& proxy,
	              Poco::Net::SocketReactor& reactor,
	              uint16_t port);

	/**
	 * Tears down this statsd_server by deregistering with the reactor.
	 */
	virtual ~statsd_server();

	statsd_server(const statsd_server&) = delete;
	statsd_server& operator=(const statsd_server&) = delete;

private:
	/**
	 * The initial size of m_read_buffer.  The buffer will grow, as needed.
	 */
	static const std::vector<char>::size_type INITIAL_READ_SIZE = 512;

	/** Invoked by the reactor when there is data to read. */
	void on_read(Poco::Net::ReadableNotification* notification);

	/** Invoked by the reactor when there is an error. */
	void on_error(Poco::Net::ErrorNotification* notification);

	/**
	 * Creates a DatagramSocket, either IPv4 or IPv6, depending on the
	 * given address.
	 */
	std::unique_ptr<Poco::Net::DatagramSocket> make_socket(
			const Poco::Net::SocketAddress& address);

	const std::string m_containerid;
	statsd_stats_destination& m_statsite;
	std::unique_ptr<Poco::Net::DatagramSocket> m_ipv4_socket;
	std::unique_ptr<Poco::Net::DatagramSocket> m_ipv6_socket;
	Poco::Net::SocketReactor& m_reactor;
	Poco::Observer<statsd_server, Poco::Net::ReadableNotification> m_read_obs;
	Poco::Observer<statsd_server, Poco::Net::ErrorNotification> m_error_obs;
	std::vector<char> m_read_buffer;
};
