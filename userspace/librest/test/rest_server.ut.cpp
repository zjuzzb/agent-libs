/**
 * @file
 *
 * Unit tests for rest_server.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_server.h"
#include "rest_request_handler_factory.h"
#include <Poco/SharedPtr.h>
#include <gtest.h>

using namespace librest;

namespace
{

using handler_factory_t = Poco::SharedPtr<rest_request_handler_factory>;

handler_factory_t create_factory()
{
	return new rest_request_handler_factory();
}

} // end namespace

/**
 * Ensure that rest_server is in the expected initial state.
 */
TEST(rest_server_test, initial_state)
{
	rest_server server(create_factory());

	ASSERT_EQ(0, server.get_port());
	ASSERT_EQ("127.0.0.1", server.get_host());
	ASSERT_FALSE(server.is_running());
}

/**
 * Ensure start starts and stop stops
 */
TEST(rest_server_test, start_stop)
{
	rest_server server(create_factory());

	server.start();
	ASSERT_TRUE(server.is_running());

	server.stop();
	ASSERT_FALSE(server.is_running());
}

/**
 * Ensure that a rest_server that was previously started and stopped can be
 * restarted.
 */
TEST(rest_server_test, start_stop_start_stop)
{
	rest_server server(create_factory());

	server.start();
	server.stop();

	server.start();
	ASSERT_TRUE(server.is_running());

	server.stop();
	ASSERT_FALSE(server.is_running());
}

/**
 * Ensure that once a rest_server is started, that a subsequent call to start()
 * has no effect.
 */
TEST(rest_server_test, start_is_idempotent)
{
	rest_server server(create_factory());

	server.start();
	ASSERT_TRUE(server.is_running());

	server.start();
	ASSERT_TRUE(server.is_running());

	server.stop();
	ASSERT_FALSE(server.is_running());
}

/**
 * Ensure that once a rest_server is stopped, that a subsequent call to stop()
 * has no effect.
 */
TEST(rest_server_test, stop_is_idempotent)
{
	rest_server server(create_factory());

	server.stop();
	ASSERT_FALSE(server.is_running());

	server.stop();
	ASSERT_FALSE(server.is_running());
}

/**
 * "Ensure" that the destructor stops the server (there's no good way to
 * verify this, but this does exercise the code for code coverage).
 */
TEST(rest_server_test, destructor_stop)
{
	rest_server server(create_factory());

	server.start();
}

/**
 * Ensure that a rest_server picks an ephemeral port if the port supplied to
 * the constructor is 0 (which it is by default).
 */
TEST(rest_server_test, start_with_0_port_yields_ephemeral_port)
{
	rest_server server(create_factory());

	server.start();

	//
	// Once the server starts, it should pick a ephemeral port.  We don't
	// know what port it'll be, but it should be non-zero.  In reality,
	// it should be in the range contained in
	// /proc/sys/net/ipv4/ip_local_port_range.  I'm not validating that...
	//
	ASSERT_NE(server.get_port(), 0);

	server.stop();
}

/**
 * Ensure that when a rest_server whose port was 0 returns 0 when the server
 * isn't running.
 */
TEST(rest_server_test, stop_with_0_port_yields_0)
{
	rest_server server(create_factory());

	server.start();
	server.stop();

	ASSERT_EQ(server.get_port(), 0);
}
