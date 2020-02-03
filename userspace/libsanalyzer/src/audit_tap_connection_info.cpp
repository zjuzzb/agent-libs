/**
 * @file
 *
 * Implementation of audit_tap_connection_info.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "audit_tap_connection_info.h"
#include "tap.pb.h"

audit_tap_connection_info::audit_tap_connection_info():
	m_error_count(0),
	m_request_count_in(0),
	m_request_count_out(0),
	m_byte_count_in(0),
	m_byte_count_out(0)
{ }

void audit_tap_connection_info::add_error_count(const uint32_t count)
{
	m_error_count += count;
}

void audit_tap_connection_info::add_request_count(const uint32_t in,
                                                  const uint32_t out)
{
	m_request_count_in += in;
	m_request_count_out += out;
}

void audit_tap_connection_info::add_byte_count(const uint64_t in,
                                               const uint64_t out)
{
	m_byte_count_in += in;
	m_byte_count_out += out;
}

void audit_tap_connection_info::emit(::tap::Connection& conn) const
{
	conn.set_errorcount(m_error_count);

	{
		auto& requestCounts = *conn.mutable_requestcounts();

		requestCounts.set_in(m_request_count_in);
		requestCounts.set_out(m_request_count_out);
		requestCounts.set_total(m_request_count_in + m_request_count_out);
	}

	{
		auto& byteCounts = *conn.mutable_bytecounts();

		byteCounts.set_in(m_byte_count_in);
		byteCounts.set_out(m_byte_count_out);
		byteCounts.set_total(m_byte_count_in + m_byte_count_out);
	}
}
