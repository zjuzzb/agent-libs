/**
 * @file
 *
 * Unit tests for audit_tap_network_connection.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "audit_tap_network_connection.h"
#include "tap.pb.h"
#include <arpa/inet.h>
#include <gtest.h>
#include <unordered_map>

TEST(audit_tap_network_connection_test, get_client_ip)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	ASSERT_EQ(client_ip, conn.get_client_ip());
}

TEST(audit_tap_network_connection_test, get_client_port)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	ASSERT_EQ(client_port, conn.get_client_port());
}

TEST(audit_tap_network_connection_test, get_client_pid)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	ASSERT_EQ(client_pid, conn.get_client_pid());
}

TEST(audit_tap_network_connection_test, get_server_ip)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	ASSERT_EQ(server_ip, conn.get_server_ip());
}

TEST(audit_tap_network_connection_test, get_server_port)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	ASSERT_EQ(server_port, conn.get_server_port());
}

TEST(audit_tap_network_connection_test, get_server_pid)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	ASSERT_EQ(server_pid, conn.get_server_pid());
}

TEST(audit_tap_network_connection_test, operator_equal_equal)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	ASSERT_TRUE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, operator_equal_not_equal_client_ip)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip + 1,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	ASSERT_FALSE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, operator_equal_not_equal_client_port)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port + 1,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	ASSERT_FALSE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, operator_equal_not_equal_client_pid)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port,
	                                   client_pid + 1,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	ASSERT_FALSE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, operator_equal_not_equal_server_ip)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip + 1,
	                                   server_port,
	                                   server_pid);

	ASSERT_FALSE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, operator_equal_not_equal_server_port)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port + 1,
	                                   server_pid);

	ASSERT_FALSE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, emit)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn(client_ip,
	                                  client_port,
	                                  client_pid,
	                                  server_ip,
	                                  server_port,
	                                  server_pid);

	::tap::Connection conn_pb;

	conn.emit(conn_pb);

	ASSERT_EQ(client_ip, conn_pb.clientipv4());
	ASSERT_EQ(client_port, conn_pb.clientport());
	ASSERT_EQ(client_pid, conn_pb.clientpid());
	ASSERT_EQ(server_ip, conn_pb.serveripv4());
	ASSERT_EQ(server_port, conn_pb.serverport());
	ASSERT_EQ(server_pid, conn_pb.serverpid());
}

TEST(audit_tap_network_connection_test, operator_equal_not_equal_server_pid)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid + 1);

	ASSERT_FALSE(conn1 == conn2);
}

TEST(audit_tap_network_connection_test, hash_equal)
{
	const uint16_t client_port = 37158;
	const uint64_t client_pid = 176182;
	const uint16_t server_port = 80;
	const uint64_t server_pid = 0;
	uint32_t client_ip = 0;
	uint32_t server_ip = 0;

	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.10", &client_ip));
	ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.20", &server_ip));

	audit_tap_network_connection conn1(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection conn2(client_ip,
	                                   client_port,
	                                   client_pid,
	                                   server_ip,
	                                   server_port,
	                                   server_pid);

	audit_tap_network_connection::hash hasher;

	ASSERT_EQ(hasher(conn1), hasher(conn2));
}
