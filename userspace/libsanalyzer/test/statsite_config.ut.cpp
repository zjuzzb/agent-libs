/**
 * @file
 *
 * Unit tests for namspace statsite_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsite_config.h"
#include "scoped_configuration.h"
#include <set>
#include <sstream>
#include <string>
#include <gtest.h>

using namespace libsanalyzer;

/**
 * Ensure that by default, is_enabled() returns DEFAULT_ENABLED.
 */
TEST(statsite_config_test, default_enabled)
{
	ASSERT_EQ(statsite_config::DEFAULT_ENABLED,
	          statsite_config::is_enabled());
}

/**
 * Ensure that by default, get_flush_interval() returns DEFAULT_FLUSH_INTERVAL.
 */
TEST(statsite_config_test, default_flush_interval)
{
	ASSERT_EQ(statsite_config::DEFAULT_FLUSH_INTERVAL,
	          statsite_config::get_flush_interval());
}

/**
 * Ensure that by default, get_udp_port() returns DEFAULT_STATSD_PORT.
 */
TEST(statsite_config_test, default_udp_port)
{
	ASSERT_EQ(statsite_config::DEFAULT_STATSD_PORT,
	          statsite_config::get_udp_port());
}

/**
 * Ensure that by default, get_tcp_port() returns DEFAULT_STATSD_PORT.
 */
TEST(statsite_config_test, default_tcp_port)
{
	ASSERT_EQ(statsite_config::DEFAULT_STATSD_PORT,
	          statsite_config::get_tcp_port());
}

/**
 * Ensure that by default, use_host_statsd() returns DEFAULT_USE_HOST_STATSD.
 */
TEST(statsite_config_test, default_use_host_statsd)
{
	ASSERT_EQ(statsite_config::DEFAULT_USE_HOST_STATSD,
	          statsite_config::use_host_statsd());
}

/**
 * Ensure that if statsd is configured disabled, is_enabled() returns false.
 */
TEST(statsite_config_test, config_disabled)
{
	const std::string config = R"EOF(
statsd:
  enabled: false
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_FALSE(statsite_config::is_enabled());
}

/**
 * Ensure that if statsite flush interval is configured, get_flush_interval()
 * returns the configured value.
 */
TEST(statsite_config_test, config_flush_interval)
{
	const std::string config = R"EOF(
statsd:
  flush_interval: 27
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_EQ(27, statsite_config::get_flush_interval());
}

/*
 * Ensure that if the statsite UDP port is configured, get_udp_port() returns
 * the configured value.
 */
TEST(statsite_config_test, config_udp_port)
{
	const std::string config = R"EOF(
statsd:
  udp_port: 18125
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_EQ(18125, statsite_config::get_udp_port());
}

/*
 * Ensure that if the statsite TCP port is configured, get_tcp_port() returns
 * the configured value.
 */
TEST(statsite_config_test, config_tcp_port)
{
	const std::string config = R"EOF(
statsd:
  tcp_port: 18125
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_EQ(18125, statsite_config::get_tcp_port());
}

/**
 * Ensure that if use_host_statsd is configured, use_host_statsd() returns the
 * configured value.
 */
TEST(statsite_config_test, config_use_host_statsd)
{
	const std::string config = R"EOF(
statsd:
  use_host_statsd: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_TRUE(statsite_config::use_host_statsd());
}

/**
 * Ensure that if use_host_statsd is true, the UDP port is set to 0.
 */
TEST(statsite_config_test, config_use_host_statsd_udp_port_zero)
{
	const std::string config = R"EOF(
statsd:
  use_host_statsd: true
  udp_port: 12345
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_EQ(0, statsite_config::get_udp_port());
}

/**
 * Ensure that if use_host_statsd is true, the TCP port is set to 0.
 */
TEST(statsite_config_test, config_use_host_statsd_tcp_port_zero)
{
	const std::string config = R"EOF(
statsd:
  use_host_statsd: true
  tcp_port: 12345
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(enabled_config.loaded());
	ASSERT_EQ(0, statsite_config::get_tcp_port());
}

/**
 * Ensure that if statsd is disabled, write_statsite_configuration() generates
 * no output.
 */
TEST(statsite_config_test, write_statsite_config_statsd_disabled)
{
	const std::string config = R"EOF(
statsd:
  enabled: false
)EOF";
	test_helpers::scoped_configuration enabled_config(config);
	std::stringstream out;
	const std::string loglevel = "trace";
	const std::set<double> percentiles;

	ASSERT_TRUE(enabled_config.loaded());
	statsite_config::write_statsite_configuration(out, loglevel, percentiles);

	ASSERT_EQ(std::string(), out.str());
}

/**
 * Ensure that write_statsite_configuration(), when given a valid loglevel
 * and no percentiles generates the expected configuration file.
 */
TEST(statsite_config_test, write_statsite_config_valid_loglevel_no_percentiles)
{
	std::stringstream out;
	const std::string loglevel = "notice";
	const std::set<double> percentiles;
	const std::string expected_config = R"EOF(#
# WARNING: File generated automatically, do not edit. Please use "dragent.yaml" instead
#
[statsite]
bind_address = 127.0.0.1
port = 8125
udp_port = 8125
log_level = WARN
flush_interval = 1
parse_stdin = 1
)EOF";

	statsite_config::write_statsite_configuration(out, loglevel, percentiles);
	ASSERT_EQ(expected_config, out.str());
}

/**
 * Ensure that write_statsite_configuration(), when given an invalid loglevel
 * and no percentiles generates the expected configuration file (with loglevel
 * INFO).
 */
TEST(statsite_config_test, write_statsite_config_invalid_loglevel_no_percentiles)
{
	std::stringstream out;
	const std::string loglevel = "tacos are tasty";
	const std::set<double> percentiles;
	const std::string expected_config = R"EOF(#
# WARNING: File generated automatically, do not edit. Please use "dragent.yaml" instead
#
[statsite]
bind_address = 127.0.0.1
port = 8125
udp_port = 8125
log_level = INFO
flush_interval = 1
parse_stdin = 1
)EOF";

	statsite_config::write_statsite_configuration(out, loglevel, percentiles);
	ASSERT_EQ(expected_config, out.str());
}

/**
 * Ensure that write_statsite_configuration(), when given a valid loglevel
 * and one percentile generates the expected configuration file.  Ensure that
 * the quantiles line contains no comma.
 */
TEST(statsite_config_test, write_statsite_config_valid_loglevel_one_percentile)
{
	std::stringstream out;
	const std::string loglevel = "notice";
	const std::set<double> percentiles{99};
	const std::string expected_config = R"EOF(#
# WARNING: File generated automatically, do not edit. Please use "dragent.yaml" instead
#
[statsite]
bind_address = 127.0.0.1
port = 8125
udp_port = 8125
log_level = WARN
flush_interval = 1
parse_stdin = 1
quantiles = 0.99
)EOF";

	statsite_config::write_statsite_configuration(out, loglevel, percentiles);
	ASSERT_EQ(expected_config, out.str());
}

/**
 * Ensure that write_statsite_configuration(), when given a valid loglevel
 * and multiple percentiles generates the expected configuration file.
 */
TEST(statsite_config_test, write_statsite_config_valid_loglevel_multiple_percentiles)
{
	std::stringstream out;
	const std::string loglevel = "notice";
	const std::set<double> percentiles{44, 99, 77, 66, 88, 55};
	const std::string expected_config = R"EOF(#
# WARNING: File generated automatically, do not edit. Please use "dragent.yaml" instead
#
[statsite]
bind_address = 127.0.0.1
port = 8125
udp_port = 8125
log_level = WARN
flush_interval = 1
parse_stdin = 1
quantiles = 0.44,0.55,0.66,0.77,0.88,0.99
)EOF";

	statsite_config::write_statsite_configuration(out, loglevel, percentiles);
	ASSERT_EQ(expected_config, out.str());
}
