/**
 * @file
 *
 * Unit tests for statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "limits/metric_forwarding_configuration.h"
#include "scoped_config.h"
#include "statsd_emitter.h"
#include "feature_manager.h"
#include <gtest.h>

using libsanalyzer::statsd_emitter;

/**
 * Ensure that when security is disabled, get_limit() returns the configured
 * limit.
 */
TEST(statsd_emitter_test, get_limit_security_disabled)
{
	const unsigned expected_limit =
		metric_forwarding_configuration::instance().statsd_limit();
	
	ASSERT_EQ(expected_limit, statsd_emitter::get_limit());
}

/**
 * Ensure that when security is enabled, get_limit() returns the configured
 * limit plus statsd_emitter::MAX_SECURITY_METRICS.
 */
TEST(statsd_emitter_test, get_limit_security_enabled)
{
	test_helpers::scoped_config<bool> enable_security("security.enabled", true);
	feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL);

	const unsigned expected_limit =
		metric_forwarding_configuration::instance().statsd_limit() +
		statsd_emitter::MAX_SECURITY_METRICS;
	
	ASSERT_EQ(expected_limit, statsd_emitter::get_limit());
}
