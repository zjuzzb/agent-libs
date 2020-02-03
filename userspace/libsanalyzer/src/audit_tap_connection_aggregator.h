/**
 * @file
 *
 * Interface to audit_tap_connection_aggregator.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "audit_tap_connection_info.h"
#include "audit_tap_network_connection.h"
#include <functional>
#include <unordered_map>

namespace tap { class ConnectionAudit; }

class sinsp_connection;
union _ipv4tuple;

/**
 * Aggregates audit tap network audit data.  In general, information about
 * each connection is written to this aggregator during every analyzer flush
 * interval.  After audit_tap.network_audit_interval_s seconds the
 * aggregated content is flushed to the audit tap stream and the aggregator
 * is reset.  The result is every audit_tap.network_audit_interval_s
 * seconds, a summary of network connections over that period of time is
 * written to the audit tap.
 */
class audit_tap_connection_aggregator {
public:
	using clocksource_fn_t = std::function<uint64_t()>;

	/**
	 * Initialize this audit_tap_connection_aggregator with the given
	 * clocksource.
	 *
	 * @param[in] clocksource a function that returns the current time
	 *                        in nanoseconds.  This will usually be
	 *                        sinsp_utils::get_current_time_ns.
	 */
	audit_tap_connection_aggregator(clocksource_fn_t clocksource);

	/**
	 * Add the information in the given iptuple and connection to the
	 * current aggregation.
	 */
	void update_connection_info(const _ipv4tuple& iptuple,
	                            const sinsp_connection& connection);

	/**
	 * If it is time to emit the connection audit data, then emit it and
	 * reset this aggregator; otherwise, do nothing.
	 *
	 * @returns true if the content of this audit_tap_connection_aggregator
	 *          was written to the given conn_audit protobuf, false
	 *          otherwise.
	 */
	bool emit_on_schedule(tap::ConnectionAudit& conn_audit);

	/**
	 * Returns the emit interval, in nanoseconds.  The emit interval is
	 * defined (in seconds) by the configuration option
	 * audit_tap.network_audit_interval_s
	 */
	static uint64_t get_emit_interval_ns();

private:
	using map_t = std::unordered_map<audit_tap_network_connection,
	                                 audit_tap_connection_info,
	                                 audit_tap_network_connection::hash>;

	/**
	 * Reset the connection aggregation information associated with this
	 * audit_tap_network_connection to its initial state.
	 */
	void reset();

	clocksource_fn_t m_clocksource_fn;
	uint64_t m_last_emit_time_ns;
	map_t m_connections;
	uint32_t m_connection_count_in;
	uint32_t m_connection_count_out;
};
