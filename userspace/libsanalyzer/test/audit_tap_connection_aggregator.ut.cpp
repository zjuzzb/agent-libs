/**
 * @file
 *
 * Unit tests for audit_tap_connection_aggregator.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "audit_tap_connection_aggregator.h"
#include "connectinfo.h"
#include "tap.pb.h"
#include "tuples.h"
#include <arpa/inet.h>
#include <gtest.h>

namespace
{

const uint32_t DEFAULT_CLIENT_IP = 12;
const uint32_t DEFAULT_SERVER_IP = 23;
const uint16_t DEFAULT_CLIENT_PORT = 34;
const uint16_t DEFAULT_SERVER_PORT = 45;

void populate(_ipv4tuple& ip,
              const uint32_t sip = DEFAULT_CLIENT_IP,
              const uint32_t dip = DEFAULT_SERVER_IP,
              const uint16_t sport = DEFAULT_CLIENT_PORT,
              const uint16_t dport = DEFAULT_SERVER_PORT)
{
	ip.m_fields.m_sip = sip;
	ip.m_fields.m_dip = dip;
	ip.m_fields.m_sport = sport;
	ip.m_fields.m_dport = dport;
}

void populate(sinsp_connection& conn,
              const bool server,
              const uint64_t pid,
              const uint32_t count_in,
              const uint32_t count_out,
              const uint32_t bytes_in,
              const uint32_t bytes_out)
{
	if (server)
	{
		conn.m_spid = pid;
		conn.m_stid = pid;
		conn.m_dpid = 0;
		conn.m_dtid = 0;
		conn.m_metrics.m_client.m_count_in = count_in;
		conn.m_metrics.m_client.m_count_out = count_out;
		conn.m_metrics.m_client.m_bytes_in = bytes_in;
		conn.m_metrics.m_client.m_bytes_out = bytes_out;
	}
	else
	{
		conn.m_spid = 0;
		conn.m_stid = 0;
		conn.m_dpid = pid;
		conn.m_dtid = pid;
		conn.m_metrics.m_server.m_count_in = count_in;
		conn.m_metrics.m_server.m_count_out = count_out;
		conn.m_metrics.m_server.m_bytes_in = bytes_in;
		conn.m_metrics.m_server.m_bytes_out = bytes_out;
	}
}

// Wrap htonl() because using it, as defined, in an ASSERT_EQ() macro
// doesn't compile
uint32_t host_to_network(const uint32_t addr)
{
	return htonl(addr);
}

} // end namespace

TEST(audit_tap_connection_aggregator, single_server_connection_single_sample_time_too_early)
{
	uint64_t time = 1;
	auto clocksource_fn = [&time](){ return time; };

	const bool server = true;
	const uint64_t pid = 56;
	const uint32_t count_in = 67;
	const uint32_t count_out = 78;
	const uint32_t bytes_in = 89;
	const uint32_t bytes_out = 90;

	audit_tap_connection_aggregator aggr(clocksource_fn);
	_ipv4tuple ip = {};
	sinsp_connection conn;
	::tap::ConnectionAudit conn_audit;

	populate(ip);
	populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

	aggr.update_connection_info(ip, conn);

	// Note that for this an other tests we have to call emit() twice.
	// The first records the current time from the clocksource, but does
	// not emit.  Then we advance the clocksource by the emit interval,
	// then call emit again.  The second emit actually emits the data.
	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
	time += audit_tap_connection_aggregator::get_emit_interval_ns() - 1;
	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
}

TEST(audit_tap_connection_aggregator, single_server_connection_single_sample)
{
	uint64_t time = 1;
	auto clocksource_fn = [&time](){ return time; };

	const bool server = true;
	const uint64_t pid = 56;
	const uint32_t count_in = 67;
	const uint32_t count_out = 78;
	const uint32_t bytes_in = 89;
	const uint32_t bytes_out = 90;

	audit_tap_connection_aggregator aggr(clocksource_fn);
	_ipv4tuple ip = {};
	sinsp_connection conn;
	::tap::ConnectionAudit conn_audit;

	populate(ip);
	populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

	aggr.update_connection_info(ip, conn);

	// Note that for this an other tests we have to call emit() twice.
	// The first records the current time from the clocksource, but does
	// not emit.  Then we advance the clocksource by the emit interval,
	// then call emit again.  The second emit actually emits the data.
	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
	time += audit_tap_connection_aggregator::get_emit_interval_ns();
	ASSERT_TRUE(aggr.emit_on_schedule(conn_audit));

	ASSERT_EQ(0, conn_audit.connectioncountin());
	ASSERT_EQ(1, conn_audit.connectioncountout());
	ASSERT_EQ(1, conn_audit.connectioncounttotal());

	ASSERT_EQ(1, conn_audit.connections_size());

	const auto& conn_pb = conn_audit.connections(0);

	ASSERT_EQ(host_to_network(DEFAULT_CLIENT_IP), conn_pb.clientipv4());
	ASSERT_EQ(DEFAULT_CLIENT_PORT, conn_pb.clientport());
	ASSERT_EQ(pid, conn_pb.clientpid());

	ASSERT_EQ(host_to_network(DEFAULT_SERVER_IP), conn_pb.serveripv4());
	ASSERT_EQ(DEFAULT_SERVER_PORT, conn_pb.serverport());
	ASSERT_EQ(0, conn_pb.serverpid());

	{
		const auto& request_counts = conn_pb.requestcounts();

		ASSERT_EQ(count_in, request_counts.in());
		ASSERT_EQ(count_out, request_counts.out());
		ASSERT_EQ(count_in + count_out, request_counts.total());
	}

	{
		const auto& byte_counts = conn_pb.bytecounts();

		ASSERT_EQ(bytes_in, byte_counts.in());
		ASSERT_EQ(bytes_out, byte_counts.out());
		ASSERT_EQ(bytes_in + bytes_out, byte_counts.total());
	}
}

TEST(audit_tap_connection_aggregator, single_client_connection_single_sample)
{
	uint64_t time = 1;
	auto clocksource_fn = [&time](){ return time; };

	const bool server = false;
	const uint64_t pid = 56;
	const uint32_t count_in = 67;
	const uint32_t count_out = 78;
	const uint32_t bytes_in = 89;
	const uint32_t bytes_out = 90;

	audit_tap_connection_aggregator aggr(clocksource_fn);
	_ipv4tuple ip = {};
	sinsp_connection conn;
	::tap::ConnectionAudit conn_audit;

	populate(ip);
	populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

	aggr.update_connection_info(ip, conn);

	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
	time += audit_tap_connection_aggregator::get_emit_interval_ns();
	ASSERT_TRUE(aggr.emit_on_schedule(conn_audit));

	ASSERT_EQ(1, conn_audit.connectioncountin());
	ASSERT_EQ(0, conn_audit.connectioncountout());
	ASSERT_EQ(1, conn_audit.connectioncounttotal());

	ASSERT_EQ(1, conn_audit.connections_size());

	const auto& conn_pb = conn_audit.connections(0);

	ASSERT_EQ(host_to_network(DEFAULT_CLIENT_IP), conn_pb.clientipv4());
	ASSERT_EQ(DEFAULT_CLIENT_PORT, conn_pb.clientport());
	ASSERT_EQ(0, conn_pb.clientpid());

	ASSERT_EQ(host_to_network(DEFAULT_SERVER_IP), conn_pb.serveripv4());
	ASSERT_EQ(DEFAULT_SERVER_PORT, conn_pb.serverport());
	ASSERT_EQ(pid, conn_pb.serverpid());

	{
		const auto& request_counts = conn_pb.requestcounts();

		ASSERT_EQ(count_in, request_counts.in());
		ASSERT_EQ(count_out, request_counts.out());
		ASSERT_EQ(count_in + count_out, request_counts.total());
	}

	{
		const auto& byte_counts = conn_pb.bytecounts();

		ASSERT_EQ(bytes_in, byte_counts.in());
		ASSERT_EQ(bytes_out, byte_counts.out());
		ASSERT_EQ(bytes_in + bytes_out, byte_counts.total());
	}
}

TEST(audit_tap_connection_aggregator, single_server_connection_multiple_samples)
{
	uint64_t time = 1;
	auto clocksource_fn = [&time](){ return time; };

	const bool server = true;
	const uint64_t pid = 56;
	const uint32_t count_in = 67;
	const uint32_t count_out = 78;
	const uint32_t bytes_in = 89;
	const uint32_t bytes_out = 90;

	audit_tap_connection_aggregator aggr(clocksource_fn);
	_ipv4tuple ip = {};
	sinsp_connection conn;
	::tap::ConnectionAudit conn_audit;

	populate(ip);
	populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

	aggr.update_connection_info(ip, conn);
	aggr.update_connection_info(ip, conn);

	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
	time += audit_tap_connection_aggregator::get_emit_interval_ns();
	ASSERT_TRUE(aggr.emit_on_schedule(conn_audit));

	ASSERT_EQ(0, conn_audit.connectioncountin());
	ASSERT_EQ(1, conn_audit.connectioncountout());
	ASSERT_EQ(1, conn_audit.connectioncounttotal());

	ASSERT_EQ(1, conn_audit.connections_size());

	const auto& conn_pb = conn_audit.connections(0);

	ASSERT_EQ(host_to_network(DEFAULT_CLIENT_IP), conn_pb.clientipv4());
	ASSERT_EQ(DEFAULT_CLIENT_PORT, conn_pb.clientport());
	ASSERT_EQ(pid, conn_pb.clientpid());

	ASSERT_EQ(host_to_network(DEFAULT_SERVER_IP), conn_pb.serveripv4());
	ASSERT_EQ(DEFAULT_SERVER_PORT, conn_pb.serverport());
	ASSERT_EQ(0, conn_pb.serverpid());

	{
		const auto& request_counts = conn_pb.requestcounts();

		ASSERT_EQ(2 * count_in, request_counts.in());
		ASSERT_EQ(2 * count_out, request_counts.out());
		ASSERT_EQ(2 * (count_in + count_out), request_counts.total());
	}

	{
		const auto& byte_counts = conn_pb.bytecounts();

		ASSERT_EQ(2 * bytes_in, byte_counts.in());
		ASSERT_EQ(2 * bytes_out, byte_counts.out());
		ASSERT_EQ(2 * (bytes_in + bytes_out), byte_counts.total());
	}
}

TEST(audit_tap_connection_aggregator, single_client_connection_multiple_samples)
{
	uint64_t time = 1;
	auto clocksource_fn = [&time](){ return time; };

	const bool server = false;
	const uint64_t pid = 56;
	const uint32_t count_in = 67;
	const uint32_t count_out = 78;
	const uint32_t bytes_in = 89;
	const uint32_t bytes_out = 90;

	audit_tap_connection_aggregator aggr(clocksource_fn);
	_ipv4tuple ip = {};
	sinsp_connection conn;
	::tap::ConnectionAudit conn_audit;

	populate(ip);
	populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

	aggr.update_connection_info(ip, conn);
	aggr.update_connection_info(ip, conn);

	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
	time += audit_tap_connection_aggregator::get_emit_interval_ns();
	ASSERT_TRUE(aggr.emit_on_schedule(conn_audit));

	ASSERT_EQ(1, conn_audit.connectioncountin());
	ASSERT_EQ(0, conn_audit.connectioncountout());
	ASSERT_EQ(1, conn_audit.connectioncounttotal());

	ASSERT_EQ(1, conn_audit.connections_size());

	const auto& conn_pb = conn_audit.connections(0);

	ASSERT_EQ(host_to_network(DEFAULT_CLIENT_IP), conn_pb.clientipv4());
	ASSERT_EQ(DEFAULT_CLIENT_PORT, conn_pb.clientport());
	ASSERT_EQ(0, conn_pb.clientpid());

	ASSERT_EQ(host_to_network(DEFAULT_SERVER_IP), conn_pb.serveripv4());
	ASSERT_EQ(DEFAULT_SERVER_PORT, conn_pb.serverport());
	ASSERT_EQ(pid, conn_pb.serverpid());

	{
		const auto& request_counts = conn_pb.requestcounts();

		ASSERT_EQ(2 * count_in, request_counts.in());
		ASSERT_EQ(2 * count_out, request_counts.out());
		ASSERT_EQ(2 * (count_in + count_out), request_counts.total());
	}

	{
		const auto& byte_counts = conn_pb.bytecounts();

		ASSERT_EQ(2 * bytes_in, byte_counts.in());
		ASSERT_EQ(2 * bytes_out, byte_counts.out());
		ASSERT_EQ(2 * (bytes_in + bytes_out), byte_counts.total());
	}
}

TEST(audit_tap_connection_aggregator, one_client_one_server)
{
	uint64_t time = 1;
	auto clocksource_fn = [&time](){ return time; };

	const uint64_t pid = 56;
	const uint32_t count_in = 67;
	const uint32_t count_out = 78;
	const uint32_t bytes_in = 89;
	const uint32_t bytes_out = 90;

	audit_tap_connection_aggregator aggr(clocksource_fn);
	::tap::ConnectionAudit conn_audit;

	// Server connection
	{
		const bool server = true;
		_ipv4tuple ip = {};
		sinsp_connection conn;

		populate(ip);
		populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

		aggr.update_connection_info(ip, conn);
	}

	// Client connection
	{
		const bool server = false;
		_ipv4tuple ip = {};
		sinsp_connection conn;

		populate(ip, DEFAULT_CLIENT_IP + 1);
		populate(conn, server, pid, count_in, count_out, bytes_in, bytes_out);

		aggr.update_connection_info(ip, conn);
	}


	ASSERT_FALSE(aggr.emit_on_schedule(conn_audit));
	time += audit_tap_connection_aggregator::get_emit_interval_ns();
	ASSERT_TRUE(aggr.emit_on_schedule(conn_audit));

	ASSERT_EQ(1, conn_audit.connectioncountin());
	ASSERT_EQ(1, conn_audit.connectioncountout());
	ASSERT_EQ(2, conn_audit.connectioncounttotal());

	ASSERT_EQ(2, conn_audit.connections_size());

	// Given earlier test passed, we'll trust that conn_audit.connections(0)
	// and  conn_audit.connections(1) correctly represent the two
	// connections.
}
