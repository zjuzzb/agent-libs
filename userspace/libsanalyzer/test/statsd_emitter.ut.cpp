/**
 * @file
 *
 * Unit tests for statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_forwarding_configuration.h"
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
	const bool security_enabled = false;
	
	ASSERT_EQ(expected_limit, statsd_emitter::get_limit(security_enabled));
}

/**
 * Ensure that when security is enabled, get_limit() returns the configured
 * limit plus 100.
 */
TEST(statsd_emitter_test, get_limit_security_enabled)
{
	const unsigned expected_limit =
		metric_forwarding_configuration::c_statsd_max->get() + 100;
	const bool security_enabled = true;
	
	ASSERT_EQ(expected_limit, statsd_emitter::get_limit(security_enabled));
}
