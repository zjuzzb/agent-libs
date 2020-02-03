/**
 * @file
 *
 * Implementation of audit_tap_network_connection.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "audit_tap_network_connection.h"
#include "tap.pb.h"
#include <functional>

namespace {

template<typename T>
void hash_combine(std::size_t& seed, const T& v)
{
	std::hash<T> hasher;

	seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

} // end namespace


audit_tap_network_connection::audit_tap_network_connection(
		const uint32_t client_ip,
		const uint16_t client_port,
		const uint64_t client_pid,
		const uint32_t server_ip,
		const uint16_t server_port,
		const uint64_t server_pid):
	m_client_ip(client_ip),
	m_client_port(client_port),
	m_client_pid(client_pid),
	m_server_ip(server_ip),
	m_server_port(server_port),
	m_server_pid(server_pid)
{ }

bool audit_tap_network_connection::operator==(
		const audit_tap_network_connection& rhs) const
{
	return m_client_ip   == rhs.m_client_ip   &&
	       m_client_port == rhs.m_client_port &&
	       m_client_pid  == rhs.m_client_pid  &&
	       m_server_ip   == rhs.m_server_ip   &&
	       m_server_port == rhs.m_server_port &&
	       m_server_pid  == rhs.m_server_pid;
}

uint32_t audit_tap_network_connection::get_client_ip() const
{
	return m_client_ip;
}

uint16_t audit_tap_network_connection::get_client_port() const
{
	return m_client_port;
}

uint64_t audit_tap_network_connection::get_client_pid() const
{
	return m_client_pid;
}

uint32_t audit_tap_network_connection::get_server_ip() const
{
	return m_server_ip;
}

uint16_t audit_tap_network_connection::get_server_port() const
{
	return m_server_port;
}

uint64_t audit_tap_network_connection::get_server_pid() const
{
	return m_server_pid;
}

void audit_tap_network_connection::emit(::tap::Connection& conn) const
{
	conn.set_clientipv4(m_client_ip);
	conn.set_clientport(m_client_port);
	conn.set_clientpid(m_client_pid);

	conn.set_serveripv4(m_server_ip);
	conn.set_serverport(m_server_port);
	conn.set_serverpid(m_server_pid);
}

std::size_t audit_tap_network_connection::hash::operator()(
		const audit_tap_network_connection& conn) const
{
	std::size_t seed = 0;

	hash_combine<uint32_t>(seed, conn.m_client_ip);
	hash_combine<uint16_t>(seed, conn.m_client_port);
	hash_combine<uint64_t>(seed, conn.m_client_pid);

	hash_combine<uint32_t>(seed, conn.m_server_ip);
	hash_combine<uint16_t>(seed, conn.m_server_port);
	hash_combine<uint64_t>(seed, conn.m_server_pid);

	return seed;
}
