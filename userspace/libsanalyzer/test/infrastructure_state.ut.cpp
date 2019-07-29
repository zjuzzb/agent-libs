#include <gtest.h>
#include "infrastructure_state.h"
#include "configuration_manager.h"
#include "sinsp_mock.h"

class test_helper
{
public:
	static const type_config<std::string>& get_url_config()
	{
		return infrastructure_state::c_k8s_url;
	}
	static const type_config<std::string>& get_bt_auth_token()
	{
		return infrastructure_state::c_k8s_bt_auth_token;
	}
	static const type_config<std::string>& get_ca_cert()
	{
		return infrastructure_state::c_k8s_ca_certificate;
	}
	static const type_config<std::string>& get_ssl_cert()
	{
		return infrastructure_state::c_k8s_ssl_certificate;
	}
	static const type_config<std::string>& get_key()
	{
		return infrastructure_state::c_k8s_ssl_key;
	}
	static std::string normalize_path(const infrastructure_state& is, const std::string& path)
	{
		return is.normalize_path(path);
	}
	static void set_url(infrastructure_state& is, const std::string& url)
	{
		is.m_k8s_url = url;
	}
	static void configure_k8s_environment(infrastructure_state& is)
	{
		is.configure_k8s_environment();
	}
};

// checks that values set in the yaml
// are reflected in in memory constructs. mostly just checks nobody fat fingered a config
// name
TEST(infrastructure_state_test, configs)
{
	// use some values. just important that they are unlikely to be the defaults for
	// any of the actual configs
	std::string yaml_string = R"(
orch_queue_len: 146
orch_gc: 147
orch_inf_wait_time_s: 148
orch_tick_interval_ms: 149
orch_low_ticks_needed: 150
orch_low_evt_threshold: 151
orch_filter_empty: false
orch_batch_msgs_queue_len: 152
orch_batch_msgs_tick_interval_ms: 153
k8s_uri: 154
k8s_ssl_cert_type: 155
k8s_ssl_cert: 156
k8s_ssl_key: 157
k8s_ssl_key_password: 158
k8s_ca_certificate: 159
k8s_ssl_verify_certificate: true
k8s_timeout_s: 160
k8s_bt_auth_token: 161
k8s_extra_resources:
    include:
      - services
      - resourcesquotas
k8s_event_counts_log_time: 162
)";

	yaml_configuration config_yaml(yaml_string);
	ASSERT_EQ(0, config_yaml.errors().size());

	configuration_manager::instance().init_config(config_yaml);
	EXPECT_EQ(infrastructure_state::c_orchestrator_queue_len.get(), 146);
	EXPECT_EQ(infrastructure_state::c_orchestrator_gc.get(), 147);
	EXPECT_EQ(infrastructure_state::c_orchestrator_informer_wait_time_s.get(), 148);
	EXPECT_EQ(infrastructure_state::c_orchestrator_tick_interval_ms.get(), 149);
	EXPECT_EQ(infrastructure_state::c_orchestrator_low_ticks_needed.get(), 150);
	EXPECT_EQ(infrastructure_state::c_orchestrator_low_event_threshold.get(), 151);
	EXPECT_EQ(infrastructure_state::c_orchestrator_filter_empty.get(), false);
	EXPECT_EQ(infrastructure_state::c_orchestrator_batch_messages_queue_length.get(), 152);
	EXPECT_EQ(infrastructure_state::c_orchestrator_batch_messages_tick_interval_ms.get(), 153);
	EXPECT_EQ(test_helper::get_url_config().get(), "154");
	EXPECT_EQ(infrastructure_state::c_k8s_ssl_certificate_type.get(), "155");
	EXPECT_EQ(test_helper::get_ssl_cert().get(), "156");
	EXPECT_EQ(test_helper::get_key().get(), "157");
	EXPECT_EQ(infrastructure_state::c_k8s_ssl_key_password->get(), "158");
	EXPECT_EQ(test_helper::get_ca_cert().get(), "159");
	EXPECT_EQ(infrastructure_state::c_k8s_ssl_verify_certificate.get(), true);
	EXPECT_EQ(infrastructure_state::c_k8s_timeout_s.get(), 160);
	EXPECT_EQ(test_helper::get_bt_auth_token().get(), "161");
	EXPECT_EQ(infrastructure_state::c_k8s_include_types.get().size(), 2);
	EXPECT_EQ(infrastructure_state::c_k8s_event_counts_log_time.get(), 162);
}

// infrastructure state does a ton of post processing on configs generating
// derivative members. check that that stuff works right
TEST(infrastructure_state_test, config_post_processing)
{
	std::string yaml_string = R"(
k8s_uri: https://yaml_host:54321
k8s_bt_auth_token: at_path
k8s_ca_certificate: ca_path
k8s_ssl_cert: cert_path
k8s_ssl_key: key_path
)";
	
	yaml_configuration config_yaml(yaml_string);
	ASSERT_EQ(0, config_yaml.errors().size());
	configuration_manager::instance().init_config(config_yaml);

	// check that we properly normalize path
	test_helpers::sinsp_mock inspector;
	infrastructure_state is(&inspector, "/foo/bar");
	EXPECT_EQ("https://yaml_host:54321", is.get_k8s_url());
	EXPECT_EQ(is.get_k8s_ca_certificate(), "/foo/bar/ca_path");
	EXPECT_EQ(is.get_k8s_bt_auth_token(), "/foo/bar/at_path");
	EXPECT_EQ(is.get_k8s_ssl_certificate(), "/foo/bar/cert_path");
	EXPECT_EQ(is.get_k8s_ssl_key(), "/foo/bar/key_path");

	// check that path normalization works correctly on an already normalized path
	EXPECT_EQ(test_helper::normalize_path(is, "/already_normal"), "/already_normal");

	// validate configure_k8s_environment stuff
	test_helper::set_url(is, "");
	unsetenv("KUBERNETES_SERVICE_HOST");
	unsetenv("KUBERNETES_SERVICE_PORT_HTTPS");
	unsetenv("KUBERNETES_SERVICE_PORT");
	test_helper::configure_k8s_environment(is);
	EXPECT_EQ(is.get_k8s_url(), "");

	setenv("KUBERNETES_SERVICE_HOST", "some_host", true);
	setenv("KUBERNETES_SERVICE_PORT", "12345", true);
	test_helper::configure_k8s_environment(is);
	EXPECT_EQ(is.get_k8s_url(), "http://some_host:12345");

	test_helper::set_url(is, "");
	setenv("KUBERNETES_SERVICE_PORT_HTTPS", "12346", true);
	test_helper::configure_k8s_environment(is);
	EXPECT_EQ(is.get_k8s_url(), "https://some_host:12346");
}

