/**
 * @file
 *
 * Interface to audit_tap_network_connection.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdint>

namespace tap { class Connection; }

/**
 * Models a single network "connection" for audit tap (either TCP or UDP).  This
 * must be suitable as a key in a std::unordered_map.
 */
class audit_tap_network_connection {
public:
	/**
	 * Initalize this audit_tap_network_connection with the given values
	 * that uniquely identify a "connection" for audit tap.  The
	 * IP addresss should be in network byte order.
	 */
	audit_tap_network_connection(uint32_t client_ip,
	                             uint16_t client_port,
	                             uint64_t client_pid,
	                             uint32_t server_ip,
	                             uint16_t server_port,
	                             uint64_t server_pid);

	/**
	 * Returns true if this audit_tap_network_connection is equal to the
	 * given rhs, false otherwise.
	 */
	bool operator==(const audit_tap_network_connection& rhs) const;

	/** Returns the client IPv4 address. */
	uint32_t get_client_ip() const;

	/** Returns the client port. */
	uint16_t get_client_port() const;

	/**
	 * Returns the client process ID or 0 if this is a server-only
	 * connection.
	 */
	uint64_t get_client_pid() const;

	/** Returns the server IPv4 address. */
	uint32_t get_server_ip() const;

	/** Returns the server port. */
	uint16_t get_server_port() const;

	/**
	 * Returns the server process ID or 0 if this is a client-only
	 * connection.
	 */
	uint64_t get_server_pid() const;

	/**
	 * Write this audit_tap_network_connection to the given connection
	 * protobuf.
	 */
	void emit(::tap::Connection& conn) const;

	/**
	 * Functor that generates a hash value for an
	 * audit_tap_network_connection.
	 */
	struct hash {
		/** Returns the hash code for the given conn. */
		std::size_t operator()(const audit_tap_network_connection& conn) const;
	};

private:
	const uint32_t m_client_ip;
	const uint16_t m_client_port;
	const uint64_t m_client_pid;
	const uint32_t m_server_ip;
	const uint16_t m_server_port;
	const uint64_t m_server_pid;
};
