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
#include "fault_injection.h"
#include "statsd_stats_destination.h"
#include <Poco/AbstractObserver.h>
#include <Poco/Net/DatagramSocket.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/SocketNotification.h>
#include <Poco/Net/SocketReactor.h>

namespace
{

COMMON_LOGGER();

DEFINE_FAULT_INJECTOR(
		fh_cannot_create_ipv4_socket,
		"agent.userspace.libsanalyzer.statsd_server.no_ipv4_socket",
		"Mimic a failure to create an IPv4 socket");

DEFINE_FAULT_INJECTOR(
		fh_cannot_create_ipv6_socket,
		"agent.userspace.libsanalyzer.statsd_server.no_ipv6_socket",
		"Mimic a failure to create an IPv6 socket");
      

} // end namespace

const std::vector<char>::size_type statsd_server::INITIAL_READ_SIZE = 512;
const double statsd_server::RESIZE_SCALE_FACTOR = 1.2;

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
	using Poco::Net::NetException;

	try
	{
		FAULT_FIRED_INVOKE(fh_cannot_create_ipv4_socket,
				   []() { throw NetException("Injected fault"); });

		m_ipv4_socket = make_socket("127.0.0.1", port);

	}
	catch(const NetException& ex)
	{
		LOG_WARNING("Unable to bind ipv4 on containerid=%s reason=%s",
		            containerid.c_str(),
		            ex.displayText().c_str());
	}

	try
	{
		FAULT_FIRED_INVOKE(fh_cannot_create_ipv6_socket,
				   []() { throw NetException("Injected fault"); });

		m_ipv6_socket = make_socket("::1", port);
	}
	catch(const NetException& ex)
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

const std::string& statsd_server::get_container_id() const
{
	return m_containerid;
}

uint16_t statsd_server::get_ipv4_port() const
{
	if(m_ipv4_socket != nullptr)
	{
		return m_ipv4_socket->address().port();
	}
	return 0;
}

uint16_t statsd_server::get_ipv6_port() const
{
	if(m_ipv6_socket != nullptr)
	{
		return m_ipv6_socket->address().port();
	}
	return 0;
}

size_t statsd_server::get_data_buffer_capacity() const
{
	return m_read_buffer.capacity();
}

const Poco::Net::DatagramSocket* statsd_server::get_ipv4_socket() const
{
	return m_ipv4_socket.get();
}

const Poco::Net::DatagramSocket* statsd_server::get_ipv6_socket() const
{
	return m_ipv6_socket.get();
}

const Poco::AbstractObserver& statsd_server::get_read_observer() const
{
	return m_read_obs;
}

const Poco::AbstractObserver& statsd_server::get_error_observer() const
{
	return m_error_obs;
}

std::unique_ptr<Poco::Net::DatagramSocket> statsd_server::make_socket(
		const std::string& address,
		const uint16_t port)
{
	std::unique_ptr<Poco::Net::DatagramSocket> socket =
		make_unique<Poco::Net::DatagramSocket>(
				Poco::Net::SocketAddress(address, port));

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
		m_read_buffer.reserve(bytes_available * RESIZE_SCALE_FACTOR);
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

