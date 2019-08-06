/**
 * @file
 *
 * Unit tests for statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_forwarding_configuration.h"
#include "scoped_config.h"
#include "statsd_emitter.h"
#include <gtest.h>

using libsanalyzer::statsd_emitter;

/**
 * Ensure that when security is disabled, get_limit() returns the configured
 * limit.
 */
TEST(statsd_emitter_test, get_limit_security_disabled)
{
	const unsigned expected_limit =
		metric_forwarding_configuration::c_statsd_max->get();
	
	ASSERT_EQ(expected_limit, statsd_emitter::get_limit());
}

/**
 * Ensure that when security is enabled, get_limit() returns the configured
 * limit plus statsd_emitter::MAX_SECURITY_METRICS.
 */
TEST(statsd_emitter_test, get_limit_security_enabled)
{
	test_helpers::scoped_config<bool> enable_security("security.enabled", true);

	const unsigned expected_limit =
		metric_forwarding_configuration::c_statsd_max->get() +
		statsd_emitter::MAX_SECURITY_METRICS;
	
	ASSERT_EQ(expected_limit, statsd_emitter::get_limit());
}
