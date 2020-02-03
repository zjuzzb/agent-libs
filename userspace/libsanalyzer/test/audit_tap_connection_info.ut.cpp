/**
 * @file
 *
 * Unit tests for audit_tap_connection_info.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "audit_tap_connection_info.h"
#include "tap.pb.h"
#include <gtest.h>

TEST(audit_tap_connection_info_test, error_count_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	conn.set_errorcount(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, conn.errorcount());
}

TEST(audit_tap_connection_info_test, request_count_in_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	auto& requestCounts = *conn.mutable_requestcounts();

	requestCounts.set_in(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, requestCounts.in());
}

TEST(audit_tap_connection_info_test, request_count_out_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	auto& requestCounts = *conn.mutable_requestcounts();

	requestCounts.set_out(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, requestCounts.out());
}

TEST(audit_tap_connection_info_test, request_count_total_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	auto& requestCounts = *conn.mutable_requestcounts();

	requestCounts.set_total(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, requestCounts.total());
}

TEST(audit_tap_connection_info_test, byte_count_in_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	auto& byteCounts = *conn.mutable_bytecounts();

	byteCounts.set_in(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, byteCounts.in());
}

TEST(audit_tap_connection_info_test, byte_count_out_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	auto& byteCounts = *conn.mutable_bytecounts();

	byteCounts.set_out(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, byteCounts.out());
}

TEST(audit_tap_connection_info_test, byte_count_total_initially_zero)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	auto& byteCounts = *conn.mutable_bytecounts();

	byteCounts.set_total(42); // Make sure the value changes

	info.emit(conn);

	ASSERT_EQ(0, byteCounts.total());
}

TEST(audit_tap_connection_info_test, add_error_count)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_error_count(2);
	info.add_error_count(5);

	info.emit(conn);

	ASSERT_EQ(2 + 5, conn.errorcount());
}

TEST(audit_tap_connection_info_test, add_request_count_in)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_request_count(2, 5);
	info.add_request_count(14, 7);

	info.emit(conn);

	const auto& requestCounts = conn.requestcounts();

	ASSERT_EQ(2 + 14, requestCounts.in());
}

TEST(audit_tap_connection_info_test, add_request_count_out)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_request_count(2, 5);
	info.add_request_count(14, 7);

	info.emit(conn);

	const auto& requestCounts = conn.requestcounts();

	ASSERT_EQ(5 + 7, requestCounts.out());
}

TEST(audit_tap_connection_info_test, add_request_count_total)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_request_count(2, 5);
	info.add_request_count(14, 7);

	info.emit(conn);

	const auto& requestCounts = conn.requestcounts();

	ASSERT_EQ(2 + 5 + 14 + 7, requestCounts.total());
}

TEST(audit_tap_connection_info_test, add_byte_count_in)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_byte_count(2, 5);
	info.add_byte_count(14, 7);

	info.emit(conn);

	const auto& byteCounts = conn.bytecounts();

	ASSERT_EQ(2 + 14, byteCounts.in());
}

TEST(audit_tap_connection_info_test, add_byte_count_out)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_byte_count(2, 5);
	info.add_byte_count(14, 7);

	info.emit(conn);

	const auto& byteCounts = conn.bytecounts();

	ASSERT_EQ(5 + 7, byteCounts.out());
}

TEST(audit_tap_connection_info_test, add_byte_count_total)
{
	tap::Connection conn;
	audit_tap_connection_info info;

	info.add_byte_count(2, 5);
	info.add_byte_count(14, 7);

	info.emit(conn);

	const auto& byteCounts = conn.bytecounts();

	ASSERT_EQ(2 + 5 + 14 + 7, byteCounts.total());
}
