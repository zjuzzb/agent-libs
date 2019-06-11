#include <gtest.h>
#include <metric_forwarding_configuration.h>
#include <configuration_manager.h>
#include <scoped_config.h>
#include <scoped_configuration.h>
#include <scoped_sinsp_logger_capture.h>

using namespace test_helpers;

namespace
{

bool is_enabled()
{
	return configuration_manager::instance().get_config<bool>("feature_flag_metric_forwarding_configuration")->get();
}

int get_limit()
{
	return configuration_manager::instance().get_config<int>("metric_forwarding_limit")->get();
}

}

TEST(metric_forwarding_configuration_test, defaults)
{
	scoped_config<bool> config("feature_flag_metric_forwarding_configuration", true);

	ASSERT_TRUE(is_enabled());
	ASSERT_EQ(10000, get_limit());
	ASSERT_EQ(3000, metric_forwarding_configuration::c_prometheus_max->get());
	ASSERT_EQ(500, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(100, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(500, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, override_under_default_max)
{
	// Default max is 10,000. We want the total to be lower than that
	scoped_configuration config(R"(
feature_flag_metric_forwarding_configuration: true
prometheus:
  max_metrics: 100
jmx:
  limit: 101
statsd:
  limit: 102
app_checks_limit: 103
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_TRUE(is_enabled());
	ASSERT_EQ(10000, get_limit());
	ASSERT_EQ(100, metric_forwarding_configuration::c_prometheus_max->get() );
	ASSERT_EQ(101, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(102, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(103, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, override_over_default_max)
{
	// Default max is 10,000. Metrics add up to 11,000. So the divisor
	// will be 1.1 and all metrics should drop.

	scoped_configuration config(R"(
feature_flag_metric_forwarding_configuration: true
prometheus:
  max_metrics: 0
jmx:
  limit: 2500
statsd:
  limit: 6000
app_checks_limit: 2500
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_TRUE(is_enabled());
	ASSERT_EQ(10000, get_limit());
	ASSERT_EQ(0, metric_forwarding_configuration::c_prometheus_max->get() );
	ASSERT_EQ(2272, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(5454, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(2272, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, sum_hard_limit)
{
	scoped_configuration config(R"(
metric_forwarding_limit: 20000
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(10000, get_limit());
}

TEST(metric_forwarding_configuration_test, override_matches_overriden_max)
{
	// Metrics add up to 9000. Set the limit to 9000

	scoped_configuration config(R"(
feature_flag_metric_forwarding_configuration: true
metric_forwarding_limit: 9000
prometheus:
  max_metrics: 0
jmx:
  limit: 2500
statsd:
  limit: 4000
app_checks_limit: 2500
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_TRUE(is_enabled());
	ASSERT_EQ(9000, get_limit());
	ASSERT_EQ(0, metric_forwarding_configuration::c_prometheus_max->get() );
	ASSERT_EQ(2500, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(4000, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(2500, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, hidden_configs)
{

	ASSERT_TRUE(configuration_manager::instance().get_config<int>("metric_forwarding_limit")->hidden());
	ASSERT_TRUE(configuration_manager::instance().get_config<bool>("feature_flag_metric_forwarding_configuration")->hidden());
}

TEST(metric_forwarding_configuration_test, sum_is_zero)
{
	// Set the values between the old hard limit and the new hard limit
	// and they should fall back to the old hard limit when the feature
	// is off.
	// Set statsd very high.

	scoped_configuration config(R"(
feature_flag_metric_forwarding_configuration: true
metric_forwarding_limit: 0
prometheus:
  max_metrics: 4000
jmx:
  limit: 4000
statsd:
  limit: 10000
app_checks_limit: 4000
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_TRUE(is_enabled());
	ASSERT_EQ(0, get_limit());
	ASSERT_EQ(0, metric_forwarding_configuration::c_prometheus_max->get());
	ASSERT_EQ(0, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(0, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(0, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, feature_off_defaults)
{
	ASSERT_FALSE(is_enabled());
	ASSERT_EQ(3000, metric_forwarding_configuration::c_prometheus_max->get());
	ASSERT_EQ(500, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(100, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(500, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, feature_off_configured)
{
	// Set the values between the old hard limit and the new hard limit
	// and they should fall back to the old hard limit when the feature
	// is off.
	// Set statsd very high.

	scoped_configuration config(R"(
prometheus:
  max_metrics: 500
jmx:
  limit: 501
statsd:
  limit: 502
app_checks_limit: 503
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_FALSE(is_enabled());
	ASSERT_EQ(500, metric_forwarding_configuration::c_prometheus_max->get());
	ASSERT_EQ(501, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(502, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(503, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, feature_off_hard_limit)
{
	// Set the values between the old hard limit and the new hard limit
	// and they should fall back to the old hard limit when the feature
	// is off.
	// Set statsd very high.

	scoped_configuration config(R"(
prometheus:
  max_metrics: 4000
jmx:
  limit: 4000
statsd:
  limit: 15000
app_checks_limit: 4000
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_FALSE(is_enabled());
	ASSERT_EQ(3000, metric_forwarding_configuration::c_prometheus_max->get() );
	ASSERT_EQ(3000, metric_forwarding_configuration::c_jmx_max->get());
	ASSERT_EQ(3000, metric_forwarding_configuration::c_statsd_max->get());
	ASSERT_EQ(3000, metric_forwarding_configuration::c_app_checks_max->get());
}

TEST(metric_forwarding_configuration_test, print_values)
{
	scoped_config<bool> config("feature_flag_metric_forwarding_configuration", true);
	ASSERT_TRUE(is_enabled());

	scoped_sinsp_logger_capture capture;
	metric_forwarding_configuration::print();
	ASSERT_TRUE(capture.find("Metric limits are configured as follows"));
	printf("%s", capture.get().c_str());
}

TEST(metric_forwarding_configuration_test, print_adjusted)
{
	scoped_configuration config(R"(
feature_flag_metric_forwarding_configuration: true
prometheus:
  max_metrics: 4000
jmx:
  limit: 4000
statsd:
  limit: 10000
app_checks_limit: 4000
)");

	ASSERT_TRUE(is_enabled());

	scoped_sinsp_logger_capture capture;
	metric_forwarding_configuration::print();
	ASSERT_TRUE(capture.find("The limits have been adjusted as follows"));
	printf("%s", capture.get().c_str());
}

TEST(metric_forwarding_configuration_test, feature_off_print)
{
	ASSERT_FALSE(is_enabled());

	scoped_sinsp_logger_capture capture;
	// Nothing should print
	metric_forwarding_configuration::print();
	ASSERT_FALSE(capture.find("Prometheus"));
	printf("log: %s", capture.get().c_str());
}


