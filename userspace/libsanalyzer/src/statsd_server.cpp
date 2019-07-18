/**
 * @file
 *
 * Implementation of statsd_server.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#include "statsd_server.h"
#include "analyzer_utils.h"
#include "common_logger.h"
#include "statsd_stats_destination.h"
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/SocketNotification.h>
#include <Poco/Net/SocketReactor.h>

namespace
{

COMMON_LOGGER();

} // end namespace

statsd_server::statsd_server(const std::string &containerid,
                             statsd_stats_destination& proxy,
                             Poco::Net::SocketReactor& reactor,
                             const uint16_t port):
	m_containerid(containerid),
	m_statsite(proxy),
	m_reactor(reactor),
	m_read_obs(*this, &statsd_server::on_read),
	m_error_obs(*this, &statsd_server::on_error),
	m_read_buffer(INITIAL_READ_SIZE)
{
	try
	{
		m_ipv4_socket = make_socket(Poco::Net::SocketAddress("127.0.0.1", port));
	}
	catch (const Poco::Net::NetException& ex)
	{
		LOG_WARNING("Unable to bind ipv4 on containerid=%s reason=%s",
		            containerid.c_str(),
		            ex.displayText().c_str());
	}

	try
	{
		m_ipv6_socket = make_socket(Poco::Net::SocketAddress("::1", port));
	}
	catch (const Poco::Net::NetException& ex)
	{
		LOG_WARNING("Unable to bind ipv6 on containerid=%s reason=%s",
		            containerid.c_str(),
		            ex.displayText().c_str());
	}
}

statsd_server::~statsd_server()
{
	if(m_ipv4_socket)
	{
		m_reactor.removeEventHandler(*m_ipv4_socket, m_read_obs);
		m_reactor.removeEventHandler(*m_ipv4_socket, m_error_obs);
	}

	if(m_ipv6_socket)
	{
		m_reactor.removeEventHandler(*m_ipv6_socket, m_read_obs);
		m_reactor.removeEventHandler(*m_ipv6_socket, m_error_obs);
	}
}

std::unique_ptr<Poco::Net::DatagramSocket> statsd_server::make_socket(
		const Poco::Net::SocketAddress& address)
{
	std::unique_ptr<Poco::Net::DatagramSocket> socket =
		make_unique<Poco::Net::DatagramSocket>(address);

	socket->setBlocking(false);

	m_reactor.addEventHandler(*socket, m_read_obs);
	m_reactor.addEventHandler(*socket, m_error_obs);

	return socket;
}

void statsd_server::on_read(Poco::Net::ReadableNotification* const notification)
{
	// Either ipv4 or ipv6 datagram socket will come here
	Poco::Net::DatagramSocket datagram_socket(notification->socket());
	const std::vector<char>::size_type bytes_available = datagram_socket.available();

	LOG_DEBUG("bytes_available: %zu", bytes_available);
	LOG_DEBUG("ReceiveBufferSize: %d", datagram_socket.getReceiveBufferSize());

	if(bytes_available > m_read_buffer.capacity())
	{
		LOG_INFO("Resizing data buffer for %s from %zu to %zu",
		         m_containerid.c_str(),
		         m_read_buffer.capacity(),
		         bytes_available);

		// Allocate a little more than bytes_available to give a little
		// extra room so that we can hopefully avoid reallocations if
		// a future packet is just a little bigger.
		m_read_buffer.reserve(bytes_available * 1.2);
	}

	const int bytes_received = datagram_socket.receiveBytes(m_read_buffer.data(),
	                                                        m_read_buffer.capacity());

	if(bytes_received > 0)
	{
		m_statsite.send_container_metric(m_containerid,
		                                 m_read_buffer.data(),
		                                 bytes_received);
		m_statsite.send_metric(m_read_buffer.data(), bytes_received);
	}
}

void statsd_server::on_error(Poco::Net::ErrorNotification* notification)
{
	LOG_ERROR("Unexpected error on statsd server");
}

