/**
 * @file
 *
 * Implementation of audit_tap_connection_aggregator.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "audit_tap_connection_aggregator.h"
#include "connectinfo.h"
#include "common_logger.h"
#include "metrics.h"
#include "tap.pb.h"
#include "type_config.h"
#include <arpa/inet.h>

namespace {

COMMON_LOGGER();

type_config<uint64_t>::ptr c_audit_internal_s =
	type_config_builder<uint64_t>(
		60,
		"The time interval, in seconds, on which the Sysdig Monitor"
                " Agent sends network audit information",
		"audit_tap",
		"network_audit_interval_s")

	.hidden()
	.min(60)
	.build();

} // end namespace

audit_tap_connection_aggregator::audit_tap_connection_aggregator(
		audit_tap_connection_aggregator::clocksource_fn_t clocksource_fn):
	m_clocksource_fn(clocksource_fn),
	m_last_emit_time_ns(0),
	m_connections(),
	m_connection_count_in(0),
	m_connection_count_out(0)
{ }

void audit_tap_connection_aggregator::update_connection_info(
		const _ipv4tuple& iptuple,
		const sinsp_connection& connection)
{
	audit_tap_network_connection nc(htonl(iptuple.m_fields.m_sip),
	                                iptuple.m_fields.m_sport,
	                                connection.m_spid,
	                                htonl(iptuple.m_fields.m_dip),
	                                iptuple.m_fields.m_dport,
	                                connection.m_dpid);

	// Update the total connection counters only when the given connection
	// hasn't yet been counted.
	if (m_connections.find(nc) == m_connections.end())
	{
		if (connection.is_server_only())
		{
			++m_connection_count_in;
		}
		else
		{
			++m_connection_count_out;
		}
	}

	audit_tap_connection_info& info = m_connections[nc];

	info.add_error_count(connection.m_metrics.get_error_count());

	const sinsp_counter_bytes& counters =
		connection.is_server_only() ? connection.m_metrics.m_server
		                            : connection.m_metrics.m_client;

	info.add_request_count(counters.m_count_in, counters.m_count_out);
	info.add_byte_count(counters.m_bytes_in, counters.m_bytes_out);
}

bool audit_tap_connection_aggregator::emit_on_schedule(
		::tap::ConnectionAudit& conn_audit)
{
	if (m_last_emit_time_ns == 0)
	{
		// Start the clock on the first call to emit()
		m_last_emit_time_ns = m_clocksource_fn();
		return false;
	}
	else
	{
		const uint64_t now = m_clocksource_fn();

		if ((now - m_last_emit_time_ns) < get_emit_interval_ns())
		{
			return false;
		}

		m_last_emit_time_ns = now;
	}

	LOG_INFO("Emitting connection audit");

	conn_audit.set_connectioncountin(m_connection_count_in);
	conn_audit.set_connectioncountout(m_connection_count_out);
	conn_audit.set_connectioncounttotal(m_connection_count_in +
	                                    m_connection_count_out);

	for (const auto& i : m_connections)
	{
		auto& conn = *conn_audit.add_connections();

		i.first.emit(conn);
		i.second.emit(conn);
	}

	reset();

	return true;
}

void audit_tap_connection_aggregator::reset()
{
	m_connections.clear();
	m_connection_count_in = 0;
	m_connection_count_out = 0;
}

uint64_t audit_tap_connection_aggregator::get_emit_interval_ns()
{
	return c_audit_internal_s->get_value() * ONE_SECOND_IN_NS;
}
