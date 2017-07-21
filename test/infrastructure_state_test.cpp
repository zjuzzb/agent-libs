#include <Poco/Glob.h>
#include <Poco/Thread.h>
#include <Poco/NullChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/ErrorHandler.h>

#include <gtest.h>

#include <sinsp.h>
#include <analyzer.h>

using namespace std;

class infrastructure_state_test : public testing::Test
{
protected:

	//static void log_cb(std::string &&str, uint32_t sev)
	//{
	//	cout << str << "\n";
	//}

	virtual void SetUp()
	{
		m_inspector = new sinsp();
		m_analyzer = new sinsp_analyzer(m_inspector);
		m_inspector->m_analyzer = m_analyzer;

		//g_logger.remove_callback_log();
		//g_logger.add_callback_log(log_cb);

		draiosproto::congroup_update_event evt;
		draiosproto::congroup_net_port *port;
		draiosproto::congroup_uid *parent;

		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_node");
		evt.mutable_object()->mutable_uid()->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/arch"] = "amd64";
		(*evt.mutable_object()->mutable_tags())["k8s_node.name"] = "debiannzxtt";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.kubernetes.io/hostname"] = "debiannzxtt";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/os"] = "linux";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://36ea5026f1d3ee6c4f551bd7cf718944e89027f69408f416306c4f7a571be106");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("2ea9f047-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("61514632-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mysql-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("d90430e5-6e42-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "default";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("d904cea5-6e42-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "default";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.provider"] = "kubernetes";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.component"] = "apiserver";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "kubernetes";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(443);
		port->set_target_port(443);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.1");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("d90430e5-6e42-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("3d66b970-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "cassandra-422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "cassandra";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("3d66051d-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("916e6892-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "jclients";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "jclient-3160134038";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "3160134038";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "client";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("916dd9a9-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("6151e2aa-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "mysql-4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "mysql";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("61514632-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("79574611-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "client-870264856-rve63";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "870264856";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "clients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.9");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("79543649-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("fea3b13e-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "redis-943706705-p09uk";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.15");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("fea1e88e-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("aaaaaaaa-1111-aaaa-1111-aaaaaaaaaaaa");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("e6933c87-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("f2a43049-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mongo-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("169ad785-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "prod";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(80);
		port->set_target_port(80);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.246");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("e6ab0b03-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "cassandra-422472749-0sf4k";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.4");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("e6a9c465-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("e674b40e-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("f2a498c2-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "mongo-2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "mongo";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("f2a43049-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("3d3ef901-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "dev";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(27017);
		port->set_target_port(27017);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("16aa7668-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "wordpress-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("e6a968b5-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "cassandra-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://a5cb56a75bf63b278ae231ebc0ab811672f3cc1aacc8ce78d9816250d0678124");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:735763a4db0ae83c58e26337d959ca302e71e8a294279413cb50c014e532f20b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "cassandra:2.0.16";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("e6ab0b03-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://769758ee1a4feb5635807879b1f1c95b38da3d29bfb53e6ad40efa8fe0d2d051");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("857326d0-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("0a9e7d61-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mysql-4035395549-6rdnl";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.16");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("0a9d9b3d-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("e69f6a77-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://9cbbe7d1bb18723368161e9f006b810c5fd4cd97692c2f3fde67089dfddad55f");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:57c67caab3d8f9ed1fbffe159b10be52e0a0610122c16b3efea50a90ff435584";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mongo";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("495b9980-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("6d5604d8-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "wordpress-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("2ea9ed15-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-301449151-zp8im";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.20");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("2ea97311-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("2e9eac10-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("55548642-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "redis-943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "redis";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("55542efd-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("555511ac-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "redis-943706705-utmsr";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.6");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("55548642-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("3d4cd22a-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("2e9eac10-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "prod";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(8080);
		port->set_target_port(8080);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.92");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("6d572793-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "wordpress-508242932-rgajm";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "508242932";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.8");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("6d566878-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("6d48adab-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("3d4cd22a-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "dev";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(6379);
		port->set_target_port(6379);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.214");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("3d339947-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "dev";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(9042);
		port->set_target_port(9042);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.66");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://c9bdbc0232b3b3146e82bbb372d6fe593dbe976cd572bc1d155d91ac75651921");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("22a5f936-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_node");
		evt.mutable_object()->mutable_uid()->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");

		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/arch"] = "amd64";
		(*evt.mutable_object()->mutable_tags())["k8s_node.name"] = "sid";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.kubernetes.io/hostname"] = "sid";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/os"] = "linux";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("85731442-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-3897015901-py340";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.12");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("85715f0c-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("8553c302-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("8553c302-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "dev";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(8080);
		port->set_target_port(8080);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.233");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("85715f0c-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "javaapp-3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "javaapp";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 3;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 3;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("8570c4c4-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://fed6a6040230f70773494cf37c425466271313631016c41b3daf23ad71ad1e7a");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:f28808014819074ca9b8e8f3d005534718b3cb89291886fa19d8edeff46f7be6";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "wordpress";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("16ac0e1f-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_node");
		evt.mutable_object()->mutable_uid()->set_id("aaaaaaaa-1111-aaaa-1111-aaaaaaaaaaaa");

		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/arch"] = "amd64";
		(*evt.mutable_object()->mutable_tags())["k8s_node.name"] = "sysdig-cloud-production-collector-i-e2a262d2";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.kubernetes.io/hostname"] = "sysdig-cloud-production-collector-i-e2a262d2";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/os"] = "linux";

		evt.mutable_object()->add_ip_addresses("54.161.123.107");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("8570c4c4-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "java-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("916f37c2-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "jclient-3160134038-cxqp7";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3160134038";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jclients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.13");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("916e6892-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("857326d0-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-3897015901-mp8zb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.10");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("85715f0c-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("8553c302-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://385ee7e33ea79e5a28a7b6e1b2d15030d7cbe892f1b6d21b942ad8d84662b83a");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("79574611-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://09c6d82f80660a541d1dbef11570e22965f0ad288f12305392a3ca1f1bdad805");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:763176ce519bad61e9e3a03314905c323f217a32f19c8202492207ca02e3ac28";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo-statsd";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/demo-mongo-statsd";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("495b9980-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://ddc3b21287326c07cae516af8939a359e6b8bb201bddc33eb231011fa2cc442d");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:dd9fe7db52364fb422efadb450d174353003b770a20dccf1ec435acd0600d77b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "redis:2.8.19";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("555511ac-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("2ea9f047-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-301449151-4q3ys";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.21");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("2ea97311-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("2e9eac10-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("e6a9c465-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "cassandra-422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "cassandra";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("e6a968b5-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("16aadccb-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "wordpress-3014601834";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "3014601834";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "wordpress";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("16aa7668-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://6a06c0f43842d47d1b0e7dd912096f176dc73182cc956236ba26696940a6b02d");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("916f37c2-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("e6933c87-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "prod";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(6379);
		port->set_target_port(6379);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.170");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("16ac0e1f-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "wordpress-3014601834-hmylu";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3014601834";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.17");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("16aadccb-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("169ad785-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://4109f6878453f336986436c81911f608132a90b6483d2605588c74976765bc4e");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:ec161391b8c32a70b45c4eb505fb94b674a41e7de920a20d37887252e7385d61";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mysql";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("0a9e7d61-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://6a8b003592284e5ae6498b29774e8f0850a5090bb2e85c48950040e8ebeebf08");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("85731442-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("495ad8a6-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mongo-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://f92a6d9a0f21333301c258149b00bc3917d57050347406324aa05ca9ded1ae2e");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("2ea9ed15-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("f2a59f40-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mongo-2390404661-3cd5u";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.14");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("f2a498c2-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("e685c065-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://c7c05e884d82044fc72b564284065c5fd3252feda6e53d0a6824c13ea2c73b34");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:735763a4db0ae83c58e26337d959ca302e71e8a294279413cb50c014e532f20b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "cassandra:2.0.16";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("3d67365f-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("fea1e88e-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "redis-943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "redis";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("fea17303-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("61525f77-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mysql-4035395549-rk922";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.7");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("6151e2aa-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("3d5a7847-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("2ea97311-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "javaapp-301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "javaapp";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 3;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 3;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("2ea9168d-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://bf7b186f27f3727f2016bb115019a006516d2ee611a22d477e02e92f23ba2474");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("85730fb1-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://ea8923f81926b9118d32b02c7dddf321db9f6428c7bdb04a9c4d8b29a32fce4f");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:f28808014819074ca9b8e8f3d005534718b3cb89291886fa19d8edeff46f7be6";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "wordpress";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("6d572793-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://4bd98895c3a962035a344210e3c7143b407f6758d3952e1bb82f4cde1c0a8b01");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:ec161391b8c32a70b45c4eb505fb94b674a41e7de920a20d37887252e7385d61";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mysql";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("61525f77-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_namespace.label.name"] = "dev";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("3d66051d-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "cassandra-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://f91874dbc6029078178fc31ad885cb1603b3be91c7b834aa5aa99d7ebb3c492b");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:dd9fe7db52364fb422efadb450d174353003b770a20dccf1ec435acd0600d77b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "redis:2.8.19";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("fea3b13e-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("22a5f936-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "client-3814011022-7jgxo";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3814011022";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "clients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.19");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("22a4584b-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("6d566878-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "wordpress-508242932";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "508242932";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "wordpress";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("6d5604d8-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("d9059711-6e42-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "kube-system";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("916dd9a9-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "jclient-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "jclient";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_namespace.label.name"] = "prod";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("e674b40e-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "prod";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(9042);
		port->set_target_port(9042);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.40");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("495b9980-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mongo-2390404661-egj3e";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.5");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("495b3b4d-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("3d3ef901-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("2ea9168d-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "java-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("3d67365f-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "cassandra-422472749-97v2i";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.3");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("3d66b970-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("3d339947-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://b4a61bd4ddcd2925f1dd7fb6d6bc224564117204b6d3dd363981013e0e3c8c4a");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("3aa43a28-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("3aa38152-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "jclient-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "jclient";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("6d48adab-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "dev";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(80);
		port->set_target_port(80);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.187");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("3aa3e0ae-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "jclients";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "jclient-4183544332";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "4183544332";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "client";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("3aa38152-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("22a3e889-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "client-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("7953b6d5-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "client-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("85730fb1-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-3897015901-9pc7f";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.11");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("85715f0c-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("8553c302-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://b2de9cf6ea727b79af6be143cc56696e7a1b7c954bb726196cd87476324d1263");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:57c67caab3d8f9ed1fbffe159b10be52e0a0610122c16b3efea50a90ff435584";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mongo";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("f2a59f40-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://904c525f573eba3598c1dc09e35f665814ece631cdc8e356cde18fee6158f02a");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:763176ce519bad61e9e3a03314905c323f217a32f19c8202492207ca02e3ac28";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo-statsd";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/demo-mongo-statsd";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("f2a59f40-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("79543649-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "clients";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "client-870264856";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "870264856";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "client";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("7953b6d5-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("0a9d2c97-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mysql-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("e685c065-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "prod";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(27017);
		port->set_target_port(27017);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("10.3.0.94");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("3aa43a28-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "jclient-4183544332-pzoca";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "4183544332";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jclients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.23");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("3aa3e0ae-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("d99fa593-6e42-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("fea17303-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "redis-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("2ea9ec19-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-301449151-8f0f4";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.22");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("2ea97311-6e44-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("2e9eac10-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("495b3b4d-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "mongo-2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "mongo";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("495ad8a6-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("3d5a7847-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "dev";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(3306);
		port->set_target_port(3306);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("None");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("e69f6a77-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_service.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_service.selector.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_service.label.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_service.namespace"] = "prod";

		port = evt.mutable_object()->mutable_ports()->Add();
		port->set_port(3306);
		port->set_target_port(3306);
		port->set_protocol("TCP");

		evt.mutable_object()->add_ip_addresses("None");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://4e9b9773ec1bb32ff6f849566bc0f535da13b7af06ae333b4038f27bd259cd17");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("2ea9ec19-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("22a4584b-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "clients";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "client-3814011022";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "3814011022";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "client";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("22a3e889-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("0a9d9b3d-6e44-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.name"] = "mysql-4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.pod-template-hash"] = "4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_replicaset.label.name"] = "mysql";

		(*evt.mutable_object()->mutable_metrics())["replicas_desired"] = 1;
		(*evt.mutable_object()->mutable_metrics())["replicas_running"] = 1;

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d27dc14-6e43-11e7-a64a-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("0a9d2c97-6e44-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("55542efd-6e43-11e7-a64a-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "redis-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("3d19f275-6e43-11e7-a64a-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();
	}

	virtual void TearDown()
	{
		m_inspector->close();
		delete m_inspector;
		delete m_analyzer;
	}

	sinsp *m_inspector;
	sinsp_analyzer *m_analyzer;
};

TEST_F(infrastructure_state_test, all_in_one)
{
	infrastructure_state *is = m_analyzer->infra_state();

	draiosproto::orchestrator_events h_evts;

	auto evt = h_evts.mutable_events()->Add();
	evt->set_type(draiosproto::ADDED);

	evt->mutable_object()->mutable_uid()->set_kind("host");
	evt->mutable_object()->mutable_uid()->set_id("12:9c:64:ce:d1:ac");

	(*evt->mutable_object()->mutable_tags())["cloudProvider.securityGroups"] = "vpc-production-SecurityGroup-1L6K6GSRDKFE2";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.id"] = "i-e2a262d2";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.tag.Infrastructure"] = "production";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.tag.Name"] = "collector";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.tag.aws:cloudformation:logical-id"] = "Group";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.tag.aws:cloudformation:stack-id"] = "arn:aws:cloudformation:us-east-1:273107874544:stack/collector-production/6b2ba630-7500-11e4-84f8-507bb903ae0a";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.tag.aws:cloudformation:stack-name"] = "collector-production";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.region"] = "us-east-1";
	(*evt->mutable_object()->mutable_tags())["host.hostName"] = "sysdig-cloud-production-cod5b708bf-6c5a-11e7-93f8-d8cb8a319c52llector-i-e2a262d2";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.account.id"] = "273107874544";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.tag.aws:autoscaling:groupName"] = "collector-production-Group-SN0217SFJJPZ";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.name"] = "ec2-54-161-123-107.compute-1.amazonaws.com";
	(*evt->mutable_object()->mutable_tags())["cloudProvider.availabilityZone"] = "us-east-1d";

	evt->mutable_object()->add_ip_addresses("54.161.123.107");
	
	evt = h_evts.mutable_events()->Add();
	evt->set_type(draiosproto::ADDED);

	evt->mutable_object()->mutable_uid()->set_kind("host");
	evt->mutable_object()->mutable_uid()->set_id("00:50:56:2b:70:26");

	(*evt->mutable_object()->mutable_tags())["agent.tag.key1"] = "value1";
	(*evt->mutable_object()->mutable_tags())["agent.tag.key2"] = "value2";
	(*evt->mutable_object()->mutable_tags())["host.hostName"] = "sId";

	evt->mutable_object()->add_ip_addresses("192.168.1.2");

	is->refresh_host_metadata(h_evts.events());

	ASSERT_EQ(is->size(), 96);

	// Test UPDATED
	draiosproto::congroup_update_event cue;

	cue.set_type(draiosproto::ADDED);
	cue.mutable_object()->mutable_uid()->set_kind("container");
	cue.mutable_object()->mutable_uid()->set_id("docker://testUUID");

	(*cue.mutable_object()->mutable_tags())["container.imageid"] = "docker://testImageUUID";
	(*cue.mutable_object()->mutable_tags())["container.name"] = "notfoo";
	(*cue.mutable_object()->mutable_tags())["container.image"] = "notbar";

	auto parent = cue.mutable_object()->mutable_parents()->Add();
	parent->set_kind("k8s_pod");
	parent->set_id("16ac0e1f-6e44-11e7-a64a-d8cb8a319c52");

	is->load_single_event(cue);
	cue.Clear();

	cue.set_type(draiosproto::UPDATED);
	cue.mutable_object()->mutable_uid()->set_kind("container");
	cue.mutable_object()->mutable_uid()->set_id("docker://testUUID");
	(*cue.mutable_object()->mutable_tags())["container.imageid"] = "docker://testImageUUID";
	(*cue.mutable_object()->mutable_tags())["container.name"] = "foo";
	(*cue.mutable_object()->mutable_tags())["container.image"] = "bar";

	is->load_single_event(cue);
	cue.Clear();

	auto updated_congroup = is->get(make_pair("container", "docker://testUUID"));
	ASSERT_EQ(updated_congroup->tags().at("container.image"), "bar");

	// Test REMOVED
	cue.set_type(draiosproto::REMOVED);

	cue.mutable_object()->mutable_uid()->set_kind("k8s_pod");
	cue.mutable_object()->mutable_uid()->set_id("16ac0e1f-6e44-11e7-a64a-d8cb8a319c52");

	is->load_single_event(cue);
	cue.Clear();

	ASSERT_FALSE(is->has(make_pair("k8s_pod", "16ac0e1f-6e44-11e7-a64a-d8cb8a319c52")));
	ASSERT_FALSE(is->has(make_pair("container", 
		"docker://f28808014819074ca9b8e8f3d005534718b3cb89291886fa19d8edeff46f7be6")));
	ASSERT_EQ(is->get(make_pair("container", 
		"docker://f28808014819074ca9b8e8f3d005534718b3cb89291886fa19d8edeff46f7be6")), nullptr);
	ASSERT_EQ(is->size(), 94);

	// Test scope matching
	draiosproto::policy p;
	draiosproto::scope_predicate *sp;
	std::string host_id;
	std::string container_id;
	bool res;

	// host scope
	p.set_id(1);
	p.set_name("foo");
	p.set_type(draiosproto::POLICY_FALCO);
	p.set_host_scope(true);
	p.set_container_scope(false);
	sp = p.mutable_scope_predicates()->Add();
	sp->set_key("host.hostName");
	sp->add_values("sId");
	sp->set_op(draiosproto::EQ);

	container_id = "";
	host_id = "00:50:56:2b:70:26";
	res = is->match_scope(container_id, host_id, p);
	ASSERT_TRUE(res);
	// Test caching
	res = is->match_scope(container_id, host_id, p);
	ASSERT_TRUE(res);

	p.Clear();

	// both host/container scopes and also that the host has been connected to the right k8s_pod
	p.set_id(2);
	p.set_name("foo2");
	p.set_type(draiosproto::POLICY_FALCO);
	p.set_host_scope(true);
	p.set_container_scope(true);
	sp = p.mutable_scope_predicates()->Add();
	sp->set_key("host.hostName");
	sp->add_values("sId");
	sp->set_op(draiosproto::EQ);
	sp = p.mutable_scope_predicates()->Add();
	sp->set_key("kubernetes.namespace.name");
	sp->add_values("prod");
	sp->set_op(draiosproto::EQ);

	container_id = "docker://36ea5026f1d3ee6c4f551bd7cf718944e89027f69408f416306c4f7a571be106";
	res = is->match_scope(container_id, host_id, p);
	ASSERT_TRUE(res);
	res = is->match_scope(container_id, host_id, p);
	ASSERT_TRUE(res);

	// Test in-agent splitting
	std::vector<std::string> c_ids{
		"docker://ddc3b21287326c07cae516af8939a359e6b8bb201bddc33eb231011fa2cc442d",
		"docker://f91874dbc6029078178fc31ad885cb1603b3be91c7b834aa5aa99d7ebb3c492b"
	};
	std::vector<std::unique_ptr<draiosproto::container_group>> result;
	is->state_of(c_ids, result);

	std::set<std::string> expected_uids{
		"3d19f275-6e43-11e7-a64a-d8cb8a319c52",
		"55542efd-6e43-11e7-a64a-d8cb8a319c52",
		"55548642-6e43-11e7-a64a-d8cb8a319c52",
		"d99fa593-6e42-11e7-a64a-d8cb8a319c52",
		"3d4cd22a-6e43-11e7-a64a-d8cb8a319c52",
		"555511ac-6e43-11e7-a64a-d8cb8a319c52",
		"3d27dc14-6e43-11e7-a64a-d8cb8a319c52",
		"fea17303-6e43-11e7-a64a-d8cb8a319c52",
		"fea1e88e-6e43-11e7-a64a-d8cb8a319c52",
		"aaaaaaaa-1111-aaaa-1111-aaaaaaaaaaaa",
		"e6933c87-6e43-11e7-a64a-d8cb8a319c52",
		"fea3b13e-6e43-11e7-a64a-d8cb8a319c52"
	};
	for(const auto &cg : result) {
		auto it = expected_uids.find(cg->uid().id());
		if (it != expected_uids.end())
			expected_uids.erase(it);
	}

	ASSERT_EQ(result.size(), 12);
	ASSERT_TRUE(expected_uids.empty());
}