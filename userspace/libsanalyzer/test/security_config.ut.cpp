/**
 * @file
 *
 * Unit tests for security_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "security_config.h"
#include "scoped_configuration.h"
#include <gtest.h>

namespace security_config = libsanalyzer::security_config;

TEST(security_config_test, default_security_is_enabled)
{
	ASSERT_FALSE(security_config::is_enabled());
}

TEST(security_config_test, configured_security_is_enabled)
{
	const std::string config = R"EOF(
security:
  enabled: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(security_config::is_enabled());
}

TEST(security_config_test, default_policies_file)
{
	ASSERT_EQ("", security_config::get_policies_file());
}

TEST(security_config_test, configured_policies_file)
{
	const std::string config = R"EOF(
security:
  policies_file: /path/to/some/policy/file.txt
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("/path/to/some/policy/file.txt",
	          security_config::get_policies_file());
}

TEST(security_config_test, default_policies_v2_file)
{
	ASSERT_EQ("", security_config::get_policies_v2_file());
}

TEST(security_config_test, configured_policies_v2_file)
{
	const std::string config = R"EOF(
security:
  policies_v2_file: /path/to/some/policy/v2/file.txt
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("/path/to/some/policy/v2/file.txt",
	          security_config::get_policies_v2_file());
}

TEST(security_config_test, default_baselines_file)
{
	ASSERT_EQ("", security_config::get_baselines_file());
}

TEST(security_config_test, configured_baselines_file)
{
	const std::string config = R"EOF(
security:
  baselines_file: /path/to/some/baselines/file.txt
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("/path/to/some/baselines/file.txt",
	          security_config::get_baselines_file());
}

TEST(security_config_test, default_security_report_interval)
{
	ASSERT_EQ(1000000000, security_config::get_report_interval_ns());
}

TEST(security_config_test, configured_security_report_interval)
{
	const std::string config = R"EOF(
security:
  report_interval: 42
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(42, security_config::get_report_interval_ns());
}

TEST(security_config_test, default_throttled_security_report_interval)
{
	ASSERT_EQ(10000000000, security_config::get_throttled_report_interval_ns());
}

TEST(security_config_test, configured_throttled_security_report_interval)
{
	const std::string config = R"EOF(
security:
  throttled_report_interval: 24
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(24, security_config::get_throttled_report_interval_ns());
}

TEST(security_config_test, default_security_actions_poll_interval)
{
	ASSERT_EQ(100000000, security_config::get_actions_poll_interval_ns());
}

TEST(security_config_test, configured_security_actions_poll_interval)
{
	const std::string config = R"EOF(
security:
  actions_poll_interval_ns: 1234
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(1234, security_config::get_actions_poll_interval_ns());
}

TEST(security_config_test, default_security_policy_events_rate)
{
	ASSERT_DOUBLE_EQ(0.5, security_config::get_policy_events_rate());
}

TEST(security_config_test, configured_security_policy_events_rate)
{
	const std::string config = R"EOF(
security:
  policy_events_rate: 0.75
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_DOUBLE_EQ(0.75, security_config::get_policy_events_rate());
}

TEST(security_config_test, default_security_policy_events_max_burst)
{
	ASSERT_EQ(50, security_config::get_policy_events_max_burst());
}

TEST(security_config_test, configured_security_policy_events_max_burst)
{
	const std::string config = R"EOF(
security:
  policy_events_max_burst: 1357
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(1357, security_config::get_policy_events_max_burst());
}

TEST(security_config_test, default_security_send_monitor_events)
{
	ASSERT_FALSE(security_config::get_send_monitor_events());
}

TEST(security_config_test, configured_security_send_monitor_events)
{
	const std::string config = R"EOF(
security:
  send_monitor_events: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(security_config::get_send_monitor_events());
}

TEST(security_config_test, default_security_compliance_schedule)
{
	ASSERT_EQ("08:00:00Z/P1D",
	          security_config::get_default_compliance_schedule());
}

TEST(security_config_test, configured_security_compliance_schedule)
{
	const std::string config = R"EOF(
security:
  default_compliance_schedule: "13:14:15Z/P1D"
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("13:14:15Z/P1D",
	          security_config::get_default_compliance_schedule());
}

TEST(security_config_test, default_send_security_compliance_events)
{
	ASSERT_FALSE(security_config::get_send_compliance_events());
}

TEST(security_config_test, configured_send_security_compliance_events)
{
	const std::string config = R"EOF(
security:
  send_compliance_events: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(security_config::get_send_compliance_events());
}

TEST(security_config_test, default_send_security_compliance_results)
{
	ASSERT_TRUE(security_config::get_send_compliance_results());
}

TEST(security_config_test, configured_send_security_compliance_results)
{
	const std::string config = R"EOF(
security:
  send_compliance_results: false
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_FALSE(security_config::get_send_compliance_results());
}

TEST(security_config_test, default_include_desc_in_compliance_results)
{
	ASSERT_TRUE(security_config::get_include_desc_in_compliance_results());
}

TEST(security_config_test, configured_include_desc_in_compliance_results)
{
	const std::string config = R"EOF(
security:
  include_desc_compliance_results: false
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_FALSE(security_config::get_include_desc_in_compliance_results());
}

TEST(security_config_test, default_security_compliance_refresh_interval)
{
	ASSERT_EQ(120000000000, security_config::get_compliance_refresh_interval());
}

TEST(security_config_test, configured_security_compliance_refresh_interval)
{
	const std::string config = R"EOF(
security:
  compliance_refresh_interval: 54321
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(54321, security_config::get_compliance_refresh_interval());
}

TEST(security_config_test, default_compliance_kube_bench_variant)
{
	ASSERT_EQ("", security_config::get_compliance_kube_bench_variant());
}

TEST(security_config_test, configured_compliance_kube_bench_variant)
{
	const std::string config = R"EOF(
security:
  compliance_kube_bench_variant: "variant_2"
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("variant_2", security_config::get_compliance_kube_bench_variant());
}

TEST(security_config_test, default_compliance_send_failed_results)
{
	ASSERT_TRUE(security_config::get_compliance_send_failed_results());
}

TEST(security_config_test, configured_compliance_send_failed_results)
{
	const std::string config = R"EOF(
security:
  compliance_send_failed_results: false
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_FALSE(security_config::get_compliance_send_failed_results());
}

TEST(security_config_test, default_compliance_save_temp_files)
{
	ASSERT_FALSE(security_config::get_compliance_save_temp_files());
}

TEST(security_config_test, configured_compliance_save_temp_files)
{
	const std::string config = R"EOF(
security:
  compliance_save_temp_files: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(security_config::get_compliance_save_temp_files());
}

TEST(security_config_test, default_k8s_audit_server_enabled)
{
	ASSERT_TRUE(security_config::get_k8s_audit_server_enabled());
}

TEST(security_config_test, configured_k8s_audit_server_enabled)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_enabled: false
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_FALSE(security_config::get_k8s_audit_server_enabled());
}

TEST(security_config_test, default_k8s_audit_server_refresh_interval)
{
	ASSERT_EQ(120000000000,
	          security_config::get_k8s_audit_server_refresh_interval());
}

TEST(security_config_test, configured_k8s_audit_server_refresh_interval)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_refresh_interval: 2345
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(2345,
	          security_config::get_k8s_audit_server_refresh_interval());
}

TEST(security_config_test, default_audit_server_url)
{
	ASSERT_EQ("localhost", security_config::get_k8s_audit_server_url());
}

TEST(security_config_test, configured_audit_server_url)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_url: "some_url"
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("some_url", security_config::get_k8s_audit_server_url());
}

TEST(security_config_test, default_audit_server_port)
{
	ASSERT_EQ(7765, security_config::get_k8s_audit_server_port());
}

TEST(security_config_test, configured_audit_server_port)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_port: 5677
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ(5677, security_config::get_k8s_audit_server_port());
}

TEST(security_config_test, default_k8s_audit_server_tls_enabled)
{
	ASSERT_FALSE(security_config::get_k8s_audit_server_tls_enabled());
}

TEST(security_config_test, configured_k8s_audit_server_tls_enabled)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_tls_enabled: true
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_TRUE(security_config::get_k8s_audit_server_tls_enabled());
}

TEST(security_config_test, default_k8s_audit_server_x509_cert_file)
{
	ASSERT_EQ("", security_config::get_k8s_audit_server_x509_cert_file());
}

TEST(security_config_test, configured_k8s_audit_server_x509_cert_file)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_x509_cert_file: "/path/to/certificate.pem"
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("/path/to/certificate.pem",
	          security_config::get_k8s_audit_server_x509_cert_file());
}

TEST(security_config_test, default_k8s_audit_server_x509_key_file)
{
	ASSERT_EQ("", security_config::get_k8s_audit_server_x509_key_file());
}

TEST(security_config_test, configured_k8s_audit_server_x509_key_file)
{
	const std::string config = R"EOF(
security:
  k8s_audit_server_x509_key_file: "/path/to/key.pem"
)EOF";
	test_helpers::scoped_configuration enabled_config(config);

	ASSERT_EQ("/path/to/key.pem",
	          security_config::get_k8s_audit_server_x509_key_file());
}

TEST(security_config_test, set_enabled)
{
	test_helpers::scoped_configuration enabled_config;

	security_config::set_enabled(true);
	ASSERT_TRUE(security_config::is_enabled());
}

TEST(security_config_test, set_policies_file)
{
	test_helpers::scoped_configuration enabled_config;

	security_config::set_policies_file("/path/to/policies/file.txt");
	ASSERT_EQ("/path/to/policies/file.txt",
	          security_config::get_policies_file());
}

TEST(security_config_test, set_baselines_file)
{
	test_helpers::scoped_configuration enabled_config;

	security_config::set_baselines_file("/path/to/baselines/file.txt");
	ASSERT_EQ("/path/to/baselines/file.txt",
	          security_config::get_baselines_file());
}

TEST(security_config_test, set_report_interval_ns)
{
	test_helpers::scoped_configuration enabled_config;

	security_config::set_report_interval_ns(1492);
	ASSERT_EQ(1492, security_config::get_report_interval_ns());
}

TEST(security_config_test, set_throttled_report_interval_ns)
{
	test_helpers::scoped_configuration enabled_config;

	security_config::set_throttled_report_interval_ns(1996);
	ASSERT_EQ(1996, security_config::get_throttled_report_interval_ns());
}
