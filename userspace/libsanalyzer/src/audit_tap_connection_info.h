/**
 * @file
 *
 * Interface to audit_tap_connection_info.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include <cstdint>

namespace tap { class Connection; }

/**
 * Models audit tap connection information that is aggregated for network
 * audit data.
 */
class audit_tap_connection_info {
public:
	audit_tap_connection_info();

	/**
	 * Add the given count to the number of network system call errors
	 * associated with a connection.
	 */
	void add_error_count(uint32_t count);

	/**
	 * Add the given in and out request counts to the number of in and out
	 * requests processed for a connection.
	 */
	void add_request_count(uint32_t in, uint32_t out);

	/**
	 * Add the given in and out byte counts to the number of in and out
	 * byte counts processed for a connection.
	 */
	void add_byte_count(uint64_t in, uint64_t out);

	/**
	 * Write the updated data to the given conn protobuf.
	 */
	void emit(::tap::Connection& conn) const;

private:
	uint32_t m_error_count;
	uint32_t m_request_count_in;
	uint32_t m_request_count_out;
	uint64_t m_byte_count_in;
	uint64_t m_byte_count_out;
};
