#include "analyzer.h"
#include "audit_tap_handler.h"
#include "configuration_manager.h"
#include "infrastructure_state.h"
#include "secure_audit_handler.h"
#include "sinsp_mock.h"

#include <gtest.h>

#define ONE_SECOND_IN_NS 1000000000LL

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
	static const type_config<std::string>& get_key() { return infrastructure_state::c_k8s_ssl_key; }
	static std::string normalize_path(const infrastructure_state& is, const std::string& path)
	{
		return is.normalize_path(path);
	}
	static void set_url(infrastructure_state& is, const std::string& url) { is.m_k8s_url = url; }
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
	EXPECT_EQ(infrastructure_state::c_orchestrator_queue_len.get_value(), 146);
	EXPECT_EQ(infrastructure_state::c_orchestrator_gc.get_value(), 147);
	EXPECT_EQ(infrastructure_state::c_orchestrator_informer_wait_time_s.get_value(), 148);
	EXPECT_EQ(infrastructure_state::c_orchestrator_tick_interval_ms.get_value(), 149);
	EXPECT_EQ(infrastructure_state::c_orchestrator_low_ticks_needed.get_value(), 150);
	EXPECT_EQ(infrastructure_state::c_orchestrator_low_event_threshold.get_value(), 151);
	EXPECT_EQ(infrastructure_state::c_orchestrator_filter_empty.get_value(), false);
	EXPECT_EQ(infrastructure_state::c_orchestrator_batch_messages_queue_length.get_value(), 152);
	EXPECT_EQ(infrastructure_state::c_orchestrator_batch_messages_tick_interval_ms.get_value(),
	          153);
	EXPECT_EQ(test_helper::get_url_config().get_value(), "154");
	EXPECT_EQ(infrastructure_state::c_k8s_ssl_certificate_type.get_value(), "155");
	EXPECT_EQ(test_helper::get_ssl_cert().get_value(), "156");
	EXPECT_EQ(test_helper::get_key().get_value(), "157");
	EXPECT_EQ(infrastructure_state::c_k8s_ssl_key_password->get_value(), "158");
	EXPECT_EQ(test_helper::get_ca_cert().get_value(), "159");
	EXPECT_EQ(infrastructure_state::c_k8s_ssl_verify_certificate.get_value(), true);
	EXPECT_EQ(infrastructure_state::c_k8s_timeout_s.get_value(), 160);
	EXPECT_EQ(test_helper::get_bt_auth_token().get_value(), "161");
	EXPECT_EQ(infrastructure_state::c_k8s_include_types.get_value().size(), 2);
	EXPECT_EQ(infrastructure_state::c_k8s_event_counts_log_time.get_value(), 162);
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
	audit_tap_handler_dummy athd;
	null_secure_audit_handler sahd;
	null_secure_profiling_handler sphd;
	null_secure_netsec_handler snhd;
	sinsp_analyzer analyzer(&inspector,
	                        "",
	                        std::make_shared<internal_metrics>(),
	                        athd,
	                        sahd,
	                        sphd,
	                        snhd,
	                        nullptr,
	                        []() -> bool { return true; });
	infrastructure_state is(analyzer, &inspector, "/foo/bar", nullptr);
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

void fill_congroup(draiosproto::container_group& to_be_filled
		   , const std::string& kind
		   , const std::string& id
		   , const std::string& namespace_name)
{
	draiosproto::congroup_uid* uid = to_be_filled.mutable_uid();
	uid->set_kind(kind);
	uid->set_id(id);
	to_be_filled.set_namespace_(namespace_name);
}


TEST(infrastructure_state_test, connect_to_namespace)
{
	static const std::string DEFAULT_NAMESPACE_NAME = "default";

	// check that we properly normalize path
	test_helpers::sinsp_mock inspector;
	audit_tap_handler_dummy athd;
	null_secure_audit_handler sahd;
	null_secure_profiling_handler sphd;
	null_secure_netsec_handler snhd;
	sinsp_analyzer analyzer(&inspector,
	                        "",
	                        std::make_shared<internal_metrics>(),
	                        athd,
	                        sahd,
	                        sphd,
	                        snhd,
	                        nullptr,
	                        []() -> bool { return true; });
	infrastructure_state is(analyzer, &inspector, "/foo/bar", nullptr);

    	infrastructure_state::uid_t deployment_uid(std::make_pair("k8s_deployment", "spacchitempu"));

	// A deployment ADD event arrives. No namespaces yet.
	draiosproto::congroup_update_event deployment_add_event;
	deployment_add_event.set_type(draiosproto::congroup_event_type::ADDED);
	draiosproto::container_group* deployment_congroup = deployment_add_event.mutable_object();
	fill_congroup(*deployment_congroup, deployment_uid.first, deployment_uid.second, DEFAULT_NAMESPACE_NAME);
	is.handle_event(&deployment_add_event);

	// We expect that the incomplete default namespace has been created
	const auto& namespaces = is.m_k8s_namespace_store.get_namespaces();
	EXPECT_EQ(namespaces.size(), 1);
	EXPECT_EQ(namespaces.begin()->first, DEFAULT_NAMESPACE_NAME);
	EXPECT_EQ(namespaces.begin()->second.is_complete(), false);

	// No parent <-> child relationship should be established yet
	EXPECT_EQ(is.m_state[deployment_uid]->parents_size(), 0);

	// Let now simulate an ADD event for namespace default arrives
	infrastructure_state::uid_t default_namespace_uid(std::make_pair("k8s_namespace", "abcd1234"));
	draiosproto::congroup_update_event namespace_add_event;
	namespace_add_event.set_type(draiosproto::congroup_event_type::ADDED);
	draiosproto::container_group* namespace_congroup = namespace_add_event.mutable_object();
	fill_congroup(*namespace_congroup, default_namespace_uid.first, default_namespace_uid.second, DEFAULT_NAMESPACE_NAME);
	is.handle_event(&namespace_add_event);

	// We expect to have 1 namespace
	EXPECT_EQ(namespaces.size(), 1);
	// Whose name is default
	EXPECT_EQ(namespaces.begin()->first, DEFAULT_NAMESPACE_NAME);
	// And complete
	EXPECT_EQ(namespaces.begin()->second.is_complete(), true);
	// Without orphans
	EXPECT_EQ(namespaces.begin()->second.has_orphans(), false);

	// We also expect that deployment container group has a namespace parent,
	// and namespace container group has a deployment children
	draiosproto::container_group* deployement_from_state = is.m_state[deployment_uid].get();
	EXPECT_EQ(deployement_from_state->parents_size(), 1);
	EXPECT_EQ(deployement_from_state->parents(0).kind(), default_namespace_uid.first);
	EXPECT_EQ(deployement_from_state->parents(0).id(), default_namespace_uid.second);

	const draiosproto::container_group& namespace_from_state = *is.m_state[default_namespace_uid].get();
	EXPECT_EQ(namespace_from_state.children_size(), 1);
	EXPECT_EQ(namespace_from_state.children(0).kind(), deployment_uid.first);
	EXPECT_EQ(namespace_from_state.children(0).id(), deployment_uid.second);

	// Let's check now what happens when deployment is UPDATED
	draiosproto::congroup_update_event update_deployment_event;
	update_deployment_event.set_type(draiosproto::congroup_event_type::UPDATED);
	draiosproto::container_group* update_congroup = update_deployment_event.mutable_object();
	// For the sake of this test this congroup can be
	fill_congroup(*update_congroup, deployment_uid.first, deployment_uid.second, DEFAULT_NAMESPACE_NAME);

	is.handle_event(&update_deployment_event);

	// We still expect that deployment has a parent and namespace has a child
	deployement_from_state = is.m_state[deployment_uid].get();
	EXPECT_NE(deployement_from_state, nullptr);
	EXPECT_EQ(deployement_from_state->parents_size(), 1);
	EXPECT_EQ(deployement_from_state->parents(0).kind(), default_namespace_uid.first);
	EXPECT_EQ(deployement_from_state->parents(0).id(), default_namespace_uid.second);
	EXPECT_EQ(namespace_from_state.children_size(), 1);
	EXPECT_EQ(namespace_from_state.children(0).kind(), deployment_uid.first);
	EXPECT_EQ(namespace_from_state.children(0).id(), deployment_uid.second);


	{
		// Add a replicaset under the deployement
		draiosproto::congroup_update_event rs_event;
		rs_event.set_type(draiosproto::congroup_event_type::ADDED);
		draiosproto::container_group& rs_cg = *rs_event.mutable_object();
		draiosproto::congroup_uid rs_uid;
		rs_uid.set_kind("k8s_replicaset");
		rs_uid.set_id("rs_test");
		fill_congroup(rs_cg, rs_uid.kind(), rs_uid.id(), DEFAULT_NAMESPACE_NAME);
		draiosproto::congroup_uid& parent = *rs_cg.mutable_parents()->Add();
		parent.set_kind("k8s_deployment");
		parent.set_id("spacchitempu");
		is.handle_event(&rs_event);

		// Update this replicaset
		draiosproto::congroup_update_event rs_update;
		rs_update.set_type(draiosproto::congroup_event_type::UPDATED);
		auto& rs_updated_cg = *rs_update.mutable_object();
		fill_congroup(rs_updated_cg, "k8s_replicaset", "rs_test", DEFAULT_NAMESPACE_NAME);
		rs_updated_cg.mutable_parents()->Add()->CopyFrom(parent);
		is.handle_event(&rs_update);

		draiosproto::container_group& rs_from_state = *is.m_state[std::make_pair(rs_uid.kind(), rs_uid.id())].get();

		EXPECT_EQ(rs_from_state.parents_size(), 2);
		EXPECT_EQ(rs_from_state.parents(0).kind(), deployment_uid.first);
		EXPECT_EQ(rs_from_state.parents(0).id(), deployment_uid.second);
		EXPECT_EQ(rs_from_state.parents(1).kind(), default_namespace_uid.first);
		EXPECT_EQ(rs_from_state.parents(1).id(), default_namespace_uid.second);
	}


	{
		// Delete the deployment
		draiosproto::congroup_update_event delete_deployment_event;
		delete_deployment_event.set_type(draiosproto::congroup_event_type::REMOVED);
		draiosproto::container_group* delete_congroup = delete_deployment_event.mutable_object();
		fill_congroup(*delete_congroup, deployment_uid.first, deployment_uid.second, DEFAULT_NAMESPACE_NAME);
		is.handle_event(&delete_deployment_event);

		// Let's refresh the infrastructure state, in order to
		// let the congroup ttl expire
		is.refresh(120 * ONE_SECOND_IN_NS);

		// We expect namespace default has one children now
		EXPECT_EQ(namespace_from_state.children_size(), 1);
		// Namespace default in the store should not have orphans
		EXPECT_EQ(namespaces.find(DEFAULT_NAMESPACE_NAME)->second.get_orphans().empty(), true);
	}
}

TEST(infrastructure_state_test, k8s_namespace_store_test)
{
	k8s_namespace_store namespace_store;

	namespace_store.add_namespace("default");
	EXPECT_EQ(namespace_store.seen_namespace_object("default"), false);

	namespace_store.m_namespaces.find("default")->second.set_uid("namespace-abcd");
	EXPECT_EQ(namespace_store.seen_namespace_object("default"), true);

	namespace_store.add_child_to_namespace("default", "child-abcd");
	EXPECT_EQ(namespace_store.m_child_to_namespace_uid.size(), 1);

	// Remove the child with an event
	draiosproto::congroup_update_event evt;
	evt.set_type(::draiosproto::congroup_event_type::REMOVED);
	draiosproto::container_group* removed_cg = evt.mutable_object();
	auto* uid = removed_cg->mutable_uid();
	uid->set_id("child-abcd");
	uid->set_kind("k8s_qualcosa");
	namespace_store.handle_event(evt);
	EXPECT_EQ(namespace_store.m_child_to_namespace_uid.size(), 0);

	{
		draiosproto::container_group cg;
		auto* uid = cg.mutable_uid();
		uid->set_kind("k8s_namespace");
		uid->set_id("marepazzo");
		cg.set_namespace_("pazzomare");
		EXPECT_EQ(cg.namespace_(), "pazzomare");
	}

	{
		draiosproto::container_group cg;
		auto* uid = cg.mutable_uid();
		uid->set_kind("k8s_deployment");
		uid->set_id("marepazzo");
		cg.set_namespace_("wanderful_namespace");
		EXPECT_EQ(cg.namespace_(), "wanderful_namespace");
	}
}

TEST(infrastructure_state_test, allowed_kinds_test)
{
	// check that we properly normalize path
	test_helpers::sinsp_mock inspector;
	audit_tap_handler_dummy athd;
	null_secure_audit_handler sahd;
	null_secure_profiling_handler sphd;
	null_secure_netsec_handler snhd;
	sinsp_analyzer analyzer(&inspector,
	                        "",
	                        std::make_shared<internal_metrics>(),
	                        athd,
	                        sahd,
	                        sphd,
	                        snhd,
	                        nullptr,
	                        []() -> bool { return true; });
	infrastructure_state is(analyzer, &inspector, "/foo/bar", nullptr);

	draiosproto::congroup_update_event update_event;
	update_event.mutable_object()->mutable_uid()->set_kind("k8s_deployement");
	is.handle_event(&update_event);
	ASSERT_EQ(is.m_state.size(), 1);

	is.m_state.clear();
	auto* parent = update_event.mutable_object()->mutable_parents()->Add();
	parent->set_kind("Grafana");
	parent->set_id("abcd");
	is.handle_event(&update_event);
	// We need to check here that is has not added our object in the orphan structure
	ASSERT_EQ(is.m_orphans.size(), 0);
	ASSERT_EQ(is.m_state.size(), 1);

	// Now get a pod with a good parent and verify the parent ends up in m_orphans
	update_event.Clear();
	update_event.mutable_object()->mutable_uid()->set_kind(k8s_pod_store::POD_KIND);
	update_event.mutable_object()->mutable_uid()->set_id("pod_id");
	parent = update_event.mutable_object()->mutable_parents()->Add();
	parent->set_kind(k8s_pod_store::DEPLOYMENT_KIND);
	parent->set_id("dep_id");
	is.handle_event(&update_event);

	ASSERT_EQ(is.m_orphans.size(), 1);
}
