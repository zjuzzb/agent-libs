#include <gtest.h>
#include <configuration_manager.h>
#include <scoped_config.h>
#include <scoped_configuration.h>
#include "prometheus.h"

using namespace test_helpers;

namespace
{
	uint32_t get_prometheus_timeout_value()
	{
		return configuration_manager::instance().get_config<uint32_t>("prometheus.timeout")->get();
	}
}

TEST(prometheus_conf_test, defaults)
{
	scoped_config<uint32_t> config("prometheus.timeout",1);

	// Test the different ways of accessing this param
	ASSERT_EQ(1, get_prometheus_timeout_value());
	ASSERT_EQ(1, prometheus_conf::c_prometheus_timeout->get());
}

TEST(prometheus_conf_test, override_defaults)
{
	scoped_configuration config(R"(
prometheus:
  timeout: 20
)");

	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(20, prometheus_conf::c_prometheus_timeout->get());
}

TEST(prometheus_conf_test, override_default_min)
{
	// Min value of timeout is 1. If we set 0, we should see value 1
	scoped_configuration config(R"(
prometheus:
  timeout: 0
)");
	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(1, prometheus_conf::c_prometheus_timeout->get());
}

TEST(prometheus_conf_test, override_default_max)
{
	// Max value of timeout is 60. If we set over 60, we should see value 60
	scoped_configuration config(R"(
prometheus:
  timeout: 100
)");
	ASSERT_TRUE(config.loaded());
	ASSERT_EQ(60, prometheus_conf::c_prometheus_timeout->get());
}
