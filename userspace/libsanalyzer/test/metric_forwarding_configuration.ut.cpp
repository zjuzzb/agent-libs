#include <gtest.h>
#include <metric_forwarding_configuration.h>
#include <configuration_manager.h>
#include <scoped_config.h>
#include <scoped_configuration.h>
#include <scoped_sinsp_logger_capture.h>

using namespace test_helpers;
using nr = metric_forwarding_configuration::negotiation_result;

namespace
{

bool is_enabled()
{
	return configuration_manager::instance().get_config<bool>("flexible_metric_limits.enabled")->get_value();
}

}

// Ensure the defaults are set to the expected values
TEST(metric_forwarding_configuration_test, defaults)
{
	metric_forwarding_configuration mfc;
	ASSERT_EQ(3000, mfc.prometheus_limit());
	ASSERT_EQ(500, mfc.jmx_limit());
	ASSERT_EQ(100, mfc.statsd_limit());
	ASSERT_EQ(500, mfc.app_checks_limit());
}

// Ensure that before negotiation the legacy limits apply
TEST(metric_forwarding_configuration_test, before_negotiation)
{
	scoped_configuration config(R"(
prometheus:
  max_metrics: 4000
jmx:
  limit: 2500
statsd:
  limit: 6000
app_checks_limit: 2500
)");
	ASSERT_TRUE(config.loaded());

	metric_forwarding_configuration mfc;

	ASSERT_EQ(3000, mfc.prometheus_limit());
	ASSERT_EQ(2500, mfc.jmx_limit());
	ASSERT_EQ(3000, mfc.statsd_limit());
	ASSERT_EQ(2500, mfc.app_checks_limit());
}

// Ensure that before negotiation the 10k limits can be turned on. This is for
// customers that don't have 10sFlush but someone gave them the 10k recipe.
TEST(metric_forwarding_configuration_test, tenk_before_negotiation)
{
	scoped_configuration config(R"(
flexible_metric_limits:
  enabled: true
prometheus:
  max_metrics: 8000
jmx:
  limit: 2000
statsd:
  limit: 2000
app_checks_limit: 2000
)");
	ASSERT_TRUE(config.loaded());

	metric_forwarding_configuration mfc;

	ASSERT_EQ(5714, mfc.prometheus_limit());
	ASSERT_EQ(1428, mfc.jmx_limit());
	ASSERT_EQ(1428, mfc.statsd_limit());
	ASSERT_EQ(1428, mfc.app_checks_limit());
}

// Ensure that the limits drop appropriately if customers set the values
// over the negotiated limit
TEST(metric_forwarding_configuration_test, above_negotiated_limit)
{
	// Default max is 10,000. Metrics add up to 11,000. So the divisor
	// will be 1.1 and all metrics should drop.

	scoped_configuration config(R"(
prometheus:
  max_metrics: 0
jmx:
  limit: 2500
statsd:
  limit: 6000
app_checks_limit: 2500
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::USE_NEGOTIATED_VALUE, 10000);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(0, mfc.prometheus_limit() );
	ASSERT_EQ(2272, mfc.jmx_limit());
	ASSERT_EQ(5454, mfc.statsd_limit());
	ASSERT_EQ(2272, mfc.app_checks_limit());
}

// Ensure that the metrics work appropriately when below the negotiated limit
TEST(metric_forwarding_configuration_test, below_negotiated_limit)
{
	scoped_configuration config(R"(
prometheus:
  max_metrics: 30000
jmx:
  limit: 2500
statsd:
  limit: 5000
app_checks_limit: 2500
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::USE_NEGOTIATED_VALUE, 50000);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(30000, mfc.prometheus_limit() );
	ASSERT_EQ(2500, mfc.jmx_limit());
	ASSERT_EQ(5000, mfc.statsd_limit());
	ASSERT_EQ(2500, mfc.app_checks_limit());
}

// Ensure that the metrics don't change when we are at the negotiated limit
TEST(metric_forwarding_configuration_test, at_negotiated_limit)
{
	scoped_configuration config(R"(
prometheus:
  max_metrics: 80000
jmx:
  limit: 5000
statsd:
  limit: 10000
app_checks_limit: 5000
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::USE_NEGOTIATED_VALUE, 100000);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(80000, mfc.prometheus_limit() );
	ASSERT_EQ(5000, mfc.jmx_limit());
	ASSERT_EQ(10000, mfc.statsd_limit());
	ASSERT_EQ(5000, mfc.app_checks_limit());
}

// Esure that metrics drop when the backend negotiates to legacy limits
TEST(metric_forwarding_configuration_test, negotiated_legacy_limits)
{
	scoped_configuration config(R"(
prometheus:
  max_metrics: 5000
jmx:
  limit: 0
statsd:
  limit: 4000
app_checks_limit: 2500
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::USE_LEGACY_LIMITS);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(3000, mfc.prometheus_limit() );
	ASSERT_EQ(0, mfc.jmx_limit());
	ASSERT_EQ(3000, mfc.statsd_limit());
	ASSERT_EQ(2500, mfc.app_checks_limit());
}

// Ensure that we allow 10k for anyone that figured out the combination
// of configuration options. We do this to retain functionality from 
// before metric limits were negotiated.
TEST(metric_forwarding_configuration_test, negotiated_legacy_limits_cheating)
{
	scoped_configuration config(R"(
flexible_metric_limits:
  enabled: true
prometheus:
  max_metrics: 0
jmx:
  limit: 3500
statsd:
  limit: 4000
app_checks_limit: 2500
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::USE_LEGACY_LIMITS);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(0, mfc.prometheus_limit() );
	ASSERT_EQ(3500, mfc.jmx_limit());
	ASSERT_EQ(4000, mfc.statsd_limit());
	ASSERT_EQ(2500, mfc.app_checks_limit());
}

// Ensure that metrics drop when the backend doesn't negotiate metric
// limits and previous config indicates legacy.
TEST(metric_forwarding_configuration_test, non_negotiated_legacy_limits)
{
	// Metrics add up to 9000. Set the limit to 9000

	scoped_configuration config(R"(
flexible_metric_limits:
  enabled: false
prometheus:
  max_metrics: 0
jmx:
  limit: 3500
statsd:
  limit: 4000
app_checks_limit: 2500
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::NEGOTIATION_NOT_SUPPORTED);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(0, mfc.prometheus_limit() );
	ASSERT_EQ(3000, mfc.jmx_limit());
	ASSERT_EQ(3000, mfc.statsd_limit());
	ASSERT_EQ(2500, mfc.app_checks_limit());
}

// Ensure that metrics drop appropriatly when the backend doesn't negotiate metric
// limits and previous config indicates 10k.
TEST(metric_forwarding_configuration_test, non_negotiated_10k_limit)
{
	// Metrics add up to 9000. Set the limit to 9000

	scoped_configuration config(R"(
flexible_metric_limits:
  enabled: true
prometheus:
  max_metrics: 20000
jmx:
  limit: 0
statsd:
  limit: 0
app_checks_limit: 0
)");

	metric_forwarding_configuration mfc;
	mfc.set_negotiated_value(nr::NEGOTIATION_NOT_SUPPORTED);

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(10000, mfc.prometheus_limit() );
	ASSERT_EQ(0, mfc.jmx_limit());
	ASSERT_EQ(0, mfc.statsd_limit());
	ASSERT_EQ(0, mfc.app_checks_limit());
}

// Since we're dealing with the instance, make the last test set the limits to
// sane values

