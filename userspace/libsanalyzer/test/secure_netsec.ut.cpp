#include "scoped_configuration.h"
#include "secure_netsec_data_ready_handler.h"
#include "unique_ptr_resetter.h"
#include "feature_manager.h"

#include <infrastructure_state.h>
#include <analyzer.h>
#include <connectinfo.h>
#include <gtest.h>
#include <memory>
#include <scoped_config.h>
#include <secure_netsec.h>
#include "secure_netsec_helper.ut.h"
#include <sinsp_mock.h>
#include <sinsp.h>

#include <arpa/inet.h>
#include <google/protobuf/util/json_util.h>


#define INTERVAL_1s                    1000000000 //        1 sec
#define INTERVAL_30s                  30000000000 //       30 sec
#define INTERVAL_60s                  60000000000 //        1 min
#define REPORT_INTERVAL_VALID_1m30s   90000000000 // 1 min 30 sec
#define K8S_CLUSTER_CIDR             "8.0.0.0/24"
#define K8S_SERVICE_CIDR             "9.0.0.0/24"

using namespace test_helpers;

audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_audit_handler;
null_secure_profiling_handler g_secure_profiling_handler;
null_secure_netsec_handler g_secure_netsec_handler;
sinsp_analyzer::flush_queue g_queue(1000);

namespace
{
class external_processor_dummy : public libsinsp::event_processor
{
	void on_capture_start() override {}
	void process_event(sinsp_evt* evt, libsinsp::event_return rc) override {}
	void add_chisel_metric(statsd_metric* metric) override {}
	sinsp_threadinfo* build_threadinfo(sinsp* inspector) override
	{
		auto tinfo = new thread_analyzer_info(inspector, nullptr, 0);
		tinfo->init();
		return tinfo;
	}
};
}  // namespace

class secure_netsec_test : public ::testing::Test
{
protected:
	enum ip_proto_l4
	{
		IP_PROTO_INVALID = 0,
		IP_PROTO_ICMP = 1,
		IP_PROTO_TCP = 6,
		IP_PROTO_UDP = 17
	};

	virtual void SetUp()
	{
		scoped_config<bool> config("autodrop.enabled", false);
		scoped_config<string> k8s_uri("k8s_uri", "");
		scoped_config<bool> k8s_autodetect("k8s_autodetect", false);

		// analyzer and infrastructure state setup
		m_inspector = new sinsp_mock();
		ASSERT_NE(m_inspector, nullptr);
		m_inspector->set_mode(SCAP_MODE_CAPTURE);

		internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
		m_analyzer = new sinsp_analyzer(m_inspector,
						"/" /*root dir*/,
						int_metrics,
						g_audit_handler,
						g_secure_audit_handler,
						g_secure_profiling_handler,
						g_secure_netsec_handler,
						&g_queue,
						[]() -> bool { return true; });

		m_inspector->register_external_event_processor(*m_analyzer);
		m_inspector->open();

		m_infrastructure_state = new infrastructure_state(*m_analyzer,
								  m_inspector,
								  "/foo/bar",
								  nullptr);

		ASSERT_NE(m_infrastructure_state, nullptr);

		// secure netsec setup
		test_helpers::scoped_config<bool> enable_security("security.enabled", true);
		test_helpers::scoped_config<bool> enable_network_topology("network_topology.enabled", true);

		test_helpers::scoped_config<uint64_t> enable_network_topology_report_interval("network_topology.report_interval",
											   REPORT_INTERVAL_VALID_1m30s);
		test_helpers::scoped_config<std::string> enable_network_topology_cluster_cidr("network_topology.cluster_cidr",
											   K8S_CLUSTER_CIDR);
		test_helpers::scoped_config<std::string> enable_network_topology_service_cidr("network_topology.service_cidr",
											   K8S_SERVICE_CIDR);
		test_helpers::scoped_config<bool> enable_network_topology_randomize_start("network_topology.randomize_start",
		                                      false);

        test_helpers::scoped_config<bool> enable_network_topology_v2("network_topology.netsec_v2",
                                                                                  false);

		feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL);

		m_netsec.init(nullptr,
			      m_infrastructure_state);

		ASSERT_EQ(m_netsec.is_k8s_cidr_configured(), true);
		ASSERT_EQ(m_netsec.get_secure_netsec_report_interval(), REPORT_INTERVAL_VALID_1m30s);

		m_netsec.set_data_handler(&m_data_ready_handler);
		m_netsec.set_internal_metrics(&m_internal_metrics_handler);
	}

	virtual void TearDown()
	{
		delete m_analyzer;
		delete m_infrastructure_state;
		delete m_inspector;
	}

	// hierarchy is HOST -> NODE ->
	//                NAMESPACE -> POD_OWNER -> POD                     -> CONTAINERS
	//                            |            |
	//                              -            [pod-without-pod-owner,
	//                              deploy        pod-from-deployment,
	//                              sts           pod-from-statefulset,
	//                              ds            pod-from-daemonset]
	//
	void load_host_and_k8s_node(const std::string& host_id,
				    const std::string& k8s_node_id)
	{
		draiosproto::congroup_update_event evt;

		// HOST
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("host");
		evt.mutable_object()->mutable_uid()->set_id(host_id);

		(*evt.mutable_object()->mutable_tags())["host.hostName"] =
			k8s_node_id + "name";

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();

		// NODE
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_node");
		evt.mutable_object()->mutable_uid()->set_id(k8s_node_id);
	}

	void load_namespace(const std::string& k8s_node_id, const std::string& ns_name)
	{
		draiosproto::congroup_update_event evt;
		draiosproto::congroup_uid* parent;

		// NAMESPACE
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("namespaceUID");
		evt.mutable_object()->set_namespace_(ns_name);

		(*evt.mutable_object()->mutable_tags())["kubernetes.namespace.name"] =
			ns_name + "-name";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id(k8s_node_id);

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();
	}

	void load_service(const std::string& service_id,
			  const std::string& service_ip,
			  const std::string& ns_name)
	{
		draiosproto::congroup_update_event evt;
		draiosproto::congroup_uid* parent;

		// POD
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id(service_id);
		evt.mutable_object()->mutable_ip_addresses()->Add(service_ip.c_str());
		evt.mutable_object()->set_namespace_(ns_name);

		(*evt.mutable_object()->mutable_tags())["kubernetes.service.name"] =
			service_id + "-name";

		(*evt.mutable_object()->mutable_internal_tags())["kubernetes.service.type"] =
			"ClusterIP";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id(ns_name);

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();
	}

	void load_pod(const std::string& k8s_node_id,
		      const bool has_pod_owner,
		      const std::string& pod_owner_kind,
		      const std::string& pod_owner_id,
		      const std::string& pod_id,
		      const std::string& pod_ip,
		      const std::string& ns_name
		)
	{
		draiosproto::congroup_update_event evt;
		draiosproto::congroup_uid* parent;
		draiosproto::congroup_uid* child;

		// POD_OWNER
		if (has_pod_owner)
		{
			evt.set_type(draiosproto::ADDED);
			evt.mutable_object()->mutable_uid()->set_kind(pod_owner_kind);
			evt.mutable_object()->mutable_uid()->set_id(pod_owner_id);
			evt.mutable_object()->set_namespace_(ns_name);

			(*evt.mutable_object()->mutable_tags())["kubernetes.deployment.name"] =
				pod_owner_id + "-name";
		}

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id(ns_name);
		child = evt.mutable_object()->mutable_children()->Add();
		child->set_kind("k8s_pod");
		child->set_id(pod_id);

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();

		// POD
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id(pod_id);
		evt.mutable_object()->mutable_ip_addresses()->Add(pod_ip.c_str());
		evt.mutable_object()->set_namespace_(ns_name);

		(*evt.mutable_object()->mutable_tags())["kubernetes.pod.name"] =
			pod_id + "-name";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id(k8s_node_id);
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id(ns_name);
		if (has_pod_owner)
		{
			parent = evt.mutable_object()->mutable_parents()->Add();
			parent->set_kind(pod_owner_kind);
			parent->set_id(pod_owner_id);
		}

		child = evt.mutable_object()->mutable_children()->Add();
		child->set_kind("container");
		child->set_id("containerID1");
		child = evt.mutable_object()->mutable_children()->Add();
		child->set_kind("container");
		child->set_id("containerID2");

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();

		// CONTAINER 1
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("containerID1");

		(*evt.mutable_object()->mutable_tags())["container.label.io.kubernetes.container.name"] =
			"elasticsearch";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("podUID");

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();

		// CONTAINER 2
		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("containerID2");

		(*evt.mutable_object()->mutable_tags())["container.label.io.kubernetes.container.name"] =
			"not-elasticsearch";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("podUID");

		m_infrastructure_state->load_single_event(evt);
		evt.Clear();
	}

	// Network byte order is defined to always be big-endian
	uint32_t ip_string_to_be(std::string ip_str)
	{
		struct sockaddr_in sa;

		// store this IP address in sa:
		inet_pton(AF_INET, ip_str.c_str(), &(sa.sin_addr));

		return sa.sin_addr.s_addr;
	}

	uint32_t ip_string_to_le(const std::string& ip_str)
	{
		return ntohl(ip_string_to_be(ip_str));
	}

	std::shared_ptr<thread_analyzer_info> get_proc(int64_t pid,
						       const std::string& name,
						       const std::string& comm,
						       const std::string& arg1,
						       const std::string& arg2,
						       const std::string& arg3)
	{
		const int64_t expected_pid = pid;
		const std::string expected_name = name;
		const std::string expected_comm = comm;
		const std::string expected_arg_1 = arg1;
		const std::string expected_arg_2 = arg2;
		const std::string expected_arg_3 = arg3;

		const std::string expected_container_id = "sysd1gcl0ud1";

		m_inspector->register_external_event_processor(*m_analyzer);
		m_inspector->build_thread()
		 	.pid(expected_pid)
		 	.comm(expected_comm)
		 	.exe(expected_name)
		 	.arg(expected_arg_1)
		 	.arg(expected_arg_2)
		 	.arg(expected_arg_3)
		 	.commit();

		std::shared_ptr<thread_analyzer_info> proc = nullptr;
		proc = sinsp_analyzer::get_thread_ref(*m_inspector,
						      expected_pid,
						      false /*don't query the os if not found*/,
						      true /*lookup only*/);

		proc->m_container_id = expected_container_id;

		thread_analyzer_info* main_thread =
			dynamic_cast<thread_analyzer_info*>(proc->get_main_thread());

		// Set process as non INTERACTIVE
		main_thread->m_th_analysis_flags &=
			~thread_analyzer_info::flags::AF_IS_INTERACTIVE_COMMAND;

		return proc;
	}

	void add_connections_helper(uint64_t ts,
				    std::shared_ptr<thread_analyzer_info> proc_cli,
				    const std::string& sip,
				    uint16_t sport,
				    std::shared_ptr<thread_analyzer_info> proc_srv,
				    const std::string& dip,
				    uint16_t dport)
	{
		const std::string expected_sip = sip;
		const std::string expected_dip = dip;

		const uint16_t expected_sport = sport;
		const uint16_t expected_dport = dport;
		const uint8_t expected_l4proto = SCAP_L4_TCP;
		const uint32_t expected_error_code = 0;

		_ipv4tuple tuple;
		sinsp_connection conn;

		// Build Tuple
		tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
		tuple.m_fields.m_sport = expected_sport;
		tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
		tuple.m_fields.m_dport = expected_dport;
		tuple.m_fields.m_l4proto = expected_l4proto;

		conn.reset();

		// Build Connection
		if (proc_cli)
		{
			conn.m_spid = proc_cli->m_pid;
			conn.m_stid = proc_cli->m_pid;
			conn.m_sfd = 1234;
			conn.m_scomm = proc_cli->m_comm;
		}
		conn.m_sproc = proc_cli;

		if (proc_srv)
		{
			conn.m_dpid = proc_srv->m_pid;
			conn.m_dtid = proc_srv->m_pid;
			conn.m_dfd = 4321;
			conn.m_dcomm = proc_srv->m_comm;
		}
		conn.m_dproc = proc_srv;

		conn.m_timestamp = ts;
		conn.m_refcount = 1;

		conn.m_analysis_flags = sinsp_connection::AF_NONE;
		conn.m_error_code = expected_error_code;

		m_netsec.add_connection_async(
			tuple,
			conn,
			std::move(
				sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));
	}

	void check_netsec_summary_counts(const secure::K8SCommunicationSummary *network_summary,
					 int ingresses,
					 int egresses,
					 int services,
					 int endpoints,
					 int pod_owners,
					 int namespaces)
	{
		ASSERT_NE(network_summary, nullptr);

		ASSERT_EQ(network_summary->clusters()[0].ingresses_size(), ingresses);
		ASSERT_EQ(network_summary->clusters()[0].egresses_size(), egresses);
		ASSERT_EQ(network_summary->clusters()[0].services_size(), services);
		ASSERT_EQ(network_summary->clusters()[0].endpoints_size(), endpoints);
		ASSERT_EQ(network_summary->clusters()[0].pod_owners_size(), pod_owners);
		ASSERT_EQ(network_summary->clusters()[0].namespaces_size(), namespaces);
	}

	void empty_flush(uint64_t ts)
	{
		// Test empty protobuf
		m_netsec.flush(ts);
		ASSERT_EQ(m_data_ready_handler.get_secure_netsec_summary_once(), nullptr);
		ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 0);

	}

	void proto_trace(const secure::K8SCommunicationSummary *network_summary)
	{
		if (network_summary)
		{
			std::string json;
			google::protobuf::util::MessageToJsonString(*network_summary, &json);
			SCOPED_TRACE(json.c_str());
		} else
		{
			SCOPED_TRACE("empty network_summary protobuf");
		}
	}

public:
	secure_netsec m_netsec;
	secure_netsec_data_ready_dummy m_data_ready_handler;
	secure_netsec_internal_metrics_dummy m_internal_metrics_handler;
	sinsp_analyzer *m_analyzer = nullptr;
	infrastructure_state *m_infrastructure_state = nullptr;
	sinsp_mock *m_inspector = nullptr;
};

class secure_netsec_test_report_config :
	public ::testing::TestWithParam<std::tuple<uint64_t, uint64_t>>
{
};

INSTANTIATE_TEST_CASE_P(
        secure_netsec_test,
        secure_netsec_test_report_config,
        ::testing::Values(
                std::make_tuple(NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MIN - 1, // invalid
				NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL),
                std::make_tuple(NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MAX,     // valid
				NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MAX),
                std::make_tuple(NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MAX + 1, // invalid
				NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL)
        ));

// if rerpot value is invalid, default to
// NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL
TEST_P(secure_netsec_test_report_config, check_report_config)
{
	test_helpers::scoped_config<uint64_t> enable_network_topology_report_interval("network_topology.report_interval",
										   std::get<0>(GetParam()));

	feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL);
	secure_netsec netsec;

	netsec.init(nullptr, nullptr);
	ASSERT_EQ(netsec.get_secure_netsec_report_interval(), std::get<1>(GetParam()));
}


// Early flushes
TEST_F(secure_netsec_test, empty_flushes)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	auto proc_cli = get_proc(5, "/opt/bin/client", "client", "", "", "");
	add_connections_helper((uint64_t)ts + 1,
			       proc_cli, "8.0.0.21", 1234,
			       nullptr, "8.0.0.22", 4321);


	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s / 3);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_EQ(network_summary, nullptr);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);

	// there's neither a client nor a server proc
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_invalid(), 0);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 0);
}

// Both client and server are local.
//
// deployment           statefulset
//  client (8.0.0.5) ->  server (8.0.0.6)
//
// - connection client -> server
// - connection client -> unresolved cidr ip
TEST_F(secure_netsec_test, local_client_and_server)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	load_host_and_k8s_node("host-id-01", "k8s-node-id-01");
	load_namespace("k8s-node-id-01", "namespace-id-01");

	// client pod
	load_pod("k8s-node-id-01",                               // k8s-node
		 true, "k8s_deployment", "deploy-client-id-01",  // pod-owner
		 "pod-client-id-01", "8.0.0.5",                  // pod
		 "namespace-id-01-name");                        // namespace

	// server pod
	load_pod("k8s-node-id-01",                               // k8s-node
		 true, "k8s_statefulset", "deploy-server-id-01", // pod-owner
		 "pod-server-id-01", "8.0.0.6",                  // pod
		 "namespace-id-01-name");                        // namespace

	// service - not used
	load_service("k8s-service-id-01",
		     "9.0.0.5",
		     "namespace-id-01-name");

	auto proc_cli = get_proc(5, "/opt/bin/client", "client", "", "", "");
	auto proc_srv = get_proc(6, "/opt/bin/server", "server", "", "", "");

	add_connections_helper((uint64_t)ts + 1,
			       proc_cli, "8.0.0.5", 9876,
			       proc_srv, "8.0.0.6", 443);

	add_connections_helper((uint64_t)ts + 2,
			       proc_cli, "8.0.0.5", 9876,
			       nullptr, "99.99.99.99", 8080); // outside the CIDR

	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);

	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_NE(network_summary, nullptr);

	ASSERT_EQ(network_summary->clusters_size(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 2);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 2);

	// As this is a local connection (we have both proc_cli and
	// proc_srv), hence we count it both as an ingress and as an
	// egress connection
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 2);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 1);

	check_netsec_summary_counts(network_summary,
				    1,  // ingresses
				    2,  // egresses
				    0,  // services
				    0,  // endpoints
				    1,  // pod_owners
				    0); // namespaces
}

// CIDR configured
// out-of-k8s-cidr communication
TEST_F(secure_netsec_test, configured_cidr_out)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	// let's double-check we have the cidr configured
	ASSERT_EQ(m_netsec.is_k8s_cidr_configured(), true);

	auto proc_srv = get_proc(6, "/opt/bin/server", "server", "", "", "");
	add_connections_helper((uint64_t)ts + 1,
			       nullptr, "88.88.88.88", 1234,
			       proc_srv, "99.99.99.99", 4321); // outside the CIDR

	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_EQ(network_summary, nullptr);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_invalid(), 0);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 0);
}

// CIDR NOT configured
// out-of-k8s-cidr communication
TEST_F(secure_netsec_test, not_configured_cidr_out)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	test_helpers::scoped_config<std::string> enable_network_topology_cluster_cidr("network_topology.cluster_cidr",
										   "");
	test_helpers::scoped_config<std::string> enable_network_topology_service_cidr("network_topology.service_cidr",
										   "");
	test_helpers::scoped_config<bool> enable_network_topology_randomize_start("network_topology.randomize_start",
	                                 false);

	// let's re-init secure_netsec, and double-check we *DON'T*
	// have the cidr configured
	m_netsec.init(nullptr, m_infrastructure_state);
	ASSERT_EQ(m_netsec.is_k8s_cidr_configured(), false);

	// 2 egress connection
	auto proc_cli = get_proc(5, "/opt/bin/client", "client", "", "", "");
	add_connections_helper((uint64_t)ts + 1,
			       proc_cli, "98.0.0.21", 1234,
			       nullptr, "98.0.0.22", 4321);

	add_connections_helper((uint64_t)ts + 2,
			       proc_cli, "98.0.0.21", 1234,
			       nullptr, "98.0.0.23", 4321);

	// 1 ingress connection
	auto proc_srv = get_proc(6, "/opt/bin/server", "server", "", "", "");
	add_connections_helper((uint64_t)ts + 3,
			       nullptr, "98.0.0.21", 1234,
			       proc_srv, "98.0.0.23", 4321);

	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_NE(network_summary, nullptr);
	ASSERT_EQ(network_summary->clusters_size(), 1);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 3);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);

	// The CIDR has not been configured, we can't have any
	// increment on these counters
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 0);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 2);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 0);

	check_netsec_summary_counts(network_summary,
				    1,  // ingresses
				    2,  // egresses
				    0,  // services
				    0,  // endpoints
				    0,  // pod_owners
				    0); // namespaces
}

// Connection with missing both client and server process names
TEST_F(secure_netsec_test, invalid_connection)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	add_connections_helper((uint64_t)ts + 1,
			       nullptr, "8.0.0.21", 1234,
			       nullptr, "8.0.0.22", 4321);


	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	// empty protobuf
	ASSERT_EQ(network_summary, nullptr);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);

	// there's neither a client nor a server proc
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_invalid(), 1);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 0);
}

// Connection with empty process name
TEST_F(secure_netsec_test, missing_process_name)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	auto proc_cli = get_proc(5, "", "", "", "", "");
	add_connections_helper((uint64_t)ts + 1,
			       proc_cli, "8.0.0.21", 1234,
			       nullptr, "8.0.0.22", 4321);


	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);

	// there's neither a client nor a server proc
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_invalid(), 0);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 0);

	check_netsec_summary_counts(network_summary,
				    0,  // ingresses
				    1,  // egresses
				    0,  // services
				    0,  // endpoints
				    0,  // pod_owners
				    0); // namespaces
}

// Repeated connection
TEST_F(secure_netsec_test, repeated_connection)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	auto proc_cli = get_proc(5, "/opt/bin/client", "client", "", "", "");
	add_connections_helper((uint64_t)ts + 1,
			       proc_cli, "8.0.0.21", 1234,
			       nullptr, "8.0.0.22", 4321);
	// all these shouldn't count...
	add_connections_helper((uint64_t)ts + 2,
			       proc_cli, "8.0.0.21", 1234,
			       nullptr, "8.0.0.22", 4321);
	add_connections_helper((uint64_t)ts + 3,
			       proc_cli, "8.0.0.21", 1234,
			       nullptr, "8.0.0.22", 4321);

	auto proc_srv = get_proc(6, "/opt/bin/server", "server", "", "", "");
	add_connections_helper((uint64_t)ts + 4,
			       proc_cli, "8.0.0.21", 1234,
			       proc_srv, "8.0.0.22", 4321);

	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 4);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);

	// there's neither a client nor a server proc
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_invalid(), 0);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 4);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 0);

	check_netsec_summary_counts(network_summary,
				    1,  // ingresses
				    1,  // egresses
				    0,  // services
				    0,  // endpoints
				    0,  // pod_owners
				    0); // namespaces
}

// In this test, we repeat the same connection
TEST_F(secure_netsec_test, delayed_metadata)
{
	uint64_t ts = sinsp_utils::get_current_time_ns();
	empty_flush(ts);

	auto proc_cli = get_proc(5, "/opt/bin/client", "client", "", "", "");
	add_connections_helper((uint64_t)ts + 1,
			       proc_cli, "8.0.0.5", 1234,
			       nullptr, "8.0.0.39", 4321);


	load_host_and_k8s_node("host-id-01", "k8s-node-id-01");
	load_namespace("k8s-node-id-01", "namespace-id-01");

	// client pod
	load_pod("k8s-node-id-01",                               // k8s-node
		 true, "k8s_deployment", "deploy-client-id-01",  // pod-owner
		 "pod-client-id-01", "8.0.0.5",                  // pod
		 "namespace-id-01-name");                        // namespace

	// server pod
	load_pod("k8s-node-id-01",                               // k8s-node
		 true, "k8s_statefulset", "deploy-server-id-01", // pod-owner
		 "pod-server-id-01", "8.0.0.6",                  // pod
		 "namespace-id-01-name");                        // namespace

	// service - not used
	load_service("k8s-service-id-01",
		     "9.0.0.5",
		     "namespace-id-01-name");


	add_connections_helper((uint64_t)ts + 2,
			       proc_cli, "8.0.0.5", 1234,
			       nullptr, "8.0.0.39", 4321);

	m_netsec.flush((uint64_t)ts + (uint64_t)REPORT_INTERVAL_VALID_1m30s);
	auto network_summary = m_data_ready_handler.get_secure_netsec_summary_once();
	proto_trace(network_summary);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_n_sent_protobufs(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_count(), 2);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_connection_dropped_count(), 0);

	// there's neither a client nor a server proc
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_invalid(), 0);

	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_out(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_cidr_in(), 2);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_ingress_count(), 0);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_egress_count(), 1);
	ASSERT_EQ(m_internal_metrics_handler.get_secure_netsec_communication_resolved_owner(), 1);

	check_netsec_summary_counts(network_summary,
				    0,  // ingresses
				    1,  // egresses
				    0,  // services
				    0,  // endpoints
				    1,  // pod_owners
				    0); // namespaces
}
