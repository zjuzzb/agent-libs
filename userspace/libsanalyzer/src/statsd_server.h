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
class AbstractObserver;

namespace Net {
class DatagramSocket;
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
	 * The initial size of m_read_buffer.  The buffer will grow, as needed.
	 */
	static const std::vector<char>::size_type INITIAL_READ_SIZE;

	/**
	 * If m_read_buffer needs to be resized, this is the scale factor
	 * that statsd_server will apply to the new size to allow for
	 * future growth.
	 */
	static const double RESIZE_SCALE_FACTOR;

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

	/**
	 * Returns the container ID which which this statsd_server is
	 * associated.
	 */
	const std::string& get_container_id() const;

	/**
	 * Returns the IPv4 port to which this statsd_server is bound, or 0
	 * if this statsd_server was unable to create a listening IPv4 socket
	 * during construction.
	 */
	uint16_t get_ipv4_port() const;

	/**
	 * Returns the IPv6 port to which this statsd_server is bound, or 0
	 * if this statsd_server was unable to create a listening IPv6 socket
	 * during construction.
	 */
	uint16_t get_ipv6_port() const;

	/**
	 * Returns the current capacity of this statsd_server%'s
	 * data buffer.
	 */
	size_t get_data_buffer_capacity() const;

	/**
	 * Returns a pointer to the IPv4 socket, if one exists, otherwise
	 * returns nullptr.
	 */
	const Poco::Net::DatagramSocket* get_ipv4_socket() const;

	/**
	 * Returns a pointer to the IPv6 socket, if one exists, otherwise
	 * returns nullptr.
	 */
	const Poco::Net::DatagramSocket* get_ipv6_socket() const;

	/**
	 * Returns the read observer associated with any sockets owned by
	 * this statsd_server.
	 */
	const Poco::AbstractObserver& get_read_observer() const;

	/**
	 * Returns the error observer associated with any sockets owned by
	 * this statsd_server.
	 */
	const Poco::AbstractObserver& get_error_observer() const;

private:
	/** Invoked by the reactor when there is data to read. */
	void on_read(Poco::Net::ReadableNotification* notification);

	/** Invoked by the reactor when there is an error. */
	void on_error(Poco::Net::ErrorNotification* notification);

	/**
	 * Creates a DatagramSocket, either IPv4 or IPv6, depending on the
	 * given address.
	 *
	 * @param[in] address The IP address on which to listen (either IPv4
	 *                    or IPv6).
	 * @param[in] port    The port on which to listen.
	 */
	std::unique_ptr<Poco::Net::DatagramSocket> make_socket(
			const std::string& address,
			uint16_t port);

	const std::string m_containerid;
	statsd_stats_destination& m_statsite;
	std::unique_ptr<Poco::Net::DatagramSocket> m_ipv4_socket;
	std::unique_ptr<Poco::Net::DatagramSocket> m_ipv6_socket;
	Poco::Net::SocketReactor& m_reactor;
	Poco::Observer<statsd_server, Poco::Net::ReadableNotification> m_read_obs;
	Poco::Observer<statsd_server, Poco::Net::ErrorNotification> m_error_obs;
	std::vector<char> m_read_buffer;
};
