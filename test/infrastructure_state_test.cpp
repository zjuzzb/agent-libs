#include <gtest.h>

#include <sinsp.h>
#include <analyzer.h>

using namespace std;

class infrastructure_state_test : public testing::Test
{
protected:

	virtual void SetUp()
	{
		m_inspector = new sinsp();
		m_analyzer = new sinsp_analyzer(m_inspector);
		m_inspector->m_analyzer = m_analyzer;

		draiosproto::congroup_update_event evt;
		draiosproto::congroup_net_port *port;
		draiosproto::congroup_uid *parent;

		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("dd7384de-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "default";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_namespace.label.name"] = "dev";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("dd74deba-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "kube-system";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_namespace");
		evt.mutable_object()->mutable_uid()->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_namespace.name"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_namespace.label.name"] = "prod";


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("ff7aec3b-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "cassandra-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("3b84eeda-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "client-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("4790fb89-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "java-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("538f605f-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "jclient-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "jclient";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("0b7939c7-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mongo-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("23762b22-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mysql-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("1777e856-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "redis-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("2f867066-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "wordpress-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "dev";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("a5b36753-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "cassandra-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("e1b357e9-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "client-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("edbc8b08-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "java-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("f9ba8f7e-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "jclient-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "jclient";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("b1b22b02-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mongo-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("c9aadd43-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "mysql-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("bdaf5af4-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "redis-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_deployment");
		evt.mutable_object()->mutable_uid()->set_id("d5b63b76-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.name"] = "wordpress-deployment";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.label.app"] = "demo";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_deployment.namespace"] = "prod";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("ff7b9cad-6c59-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("ff7aec3b-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("3b857503-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("3b84eeda-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("479166c0-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("4790fb89-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("539006aa-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("538f605f-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("0b79f58e-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("0b7939c7-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("2376acd1-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("23762b22-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("17787132-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("1777e856-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("2f86e7ea-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("2f867066-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("a5b3c3cf-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("a5b36753-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("e1b3e204-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("e1b357e9-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("edbcefc9-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("edbc8b08-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("f9bb18e2-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("f9ba8f7e-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("b1b2abfc-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("b1b22b02-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("c9ab5a0c-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("c9aadd43-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("bdafe4b3-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("bdaf5af4-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_replicaset");
		evt.mutable_object()->mutable_uid()->set_id("d5b69872-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_deployment");
		parent->set_id("d5b63b76-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("dd742691-6c59-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("dd7384de-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("ff4fb44b-6c59-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("4784d0ea-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("ff5ae01c-6c59-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("ff713842-6c59-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("ff66673d-6c59-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("2f769877-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("a585a45c-6c5a-11e7-93f8-d8cb8a319c52");

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

		evt.mutable_object()->add_ip_addresses("10.3.0.86");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("edb15e0c-6c5a-11e7-93f8-d8cb8a319c52");

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

		evt.mutable_object()->add_ip_addresses("10.3.0.36");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("a5935c4b-6c5a-11e7-93f8-d8cb8a319c52");

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

		evt.mutable_object()->add_ip_addresses("10.3.0.190");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("a5a9f5fe-6c5a-11e7-93f8-d8cb8a319c52");

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
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("a59f486f-6c5a-11e7-93f8-d8cb8a319c52");

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

		evt.mutable_object()->add_ip_addresses("10.3.0.40");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_service");
		evt.mutable_object()->mutable_uid()->set_id("d5a96d55-6c5a-11e7-93f8-d8cb8a319c52");

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

		evt.mutable_object()->add_ip_addresses("10.3.0.3");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_node");
		evt.mutable_object()->mutable_uid()->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/arch"] = "amd64";
		(*evt.mutable_object()->mutable_tags())["k8s_node.name"] = "debiannzxtt";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.kubernetes.io/hostname"] = "debiannzxtt";
		(*evt.mutable_object()->mutable_tags())["k8s_node.label.beta.kubernetes.io/os"] = "linux";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");


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
		evt.mutable_object()->mutable_uid()->set_id("ff7c8ff7-6c59-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "cassandra-422472749-1cxhs";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.3");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("ff7b9cad-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("ff4fb44b-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://f7bb4d7358a91e67b0e4a1ebc84403605ad07c2f6f8f5f7b0e5be214c5ba3466");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:735763a4db0ae83c58e26337d959ca302e71e8a294279413cb50c014e532f20b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "cassandra:2.0.16";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("ff7c8ff7-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("3b85ebae-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "client-870264856-fnumg";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "870264856";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "clients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.8");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("3b857503-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://1c4f1c1d7b380403c40d497d050a705364dec12c60bab80a7088e736def85958");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("3b85ebae-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("4791e806-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-3897015901-18omh";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.11");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("479166c0-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("4784d0ea-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://5f3ca7dad6581b35d051724bc917c3026a9514d52d1ee56508916058c6f87023");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("4791e806-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("4791e42d-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-3897015901-hloak";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.10");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("479166c0-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("4784d0ea-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://64c02d5ee4a0dd11460604c59ece16356833563a97a9a55e103ed61107e5f261");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("4791e42d-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("4791e109-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-3897015901-qk3eu";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3897015901";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.9");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("479166c0-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("4784d0ea-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://76b0923b5a69d607a4e489e88e60802bed551ccb5a0bac7929df609ce42e0678");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("4791e109-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("53907f6e-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "jclient-3160134038-iqk3a";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3160134038";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jclients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.12");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("539006aa-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://b79796123b5ec3506eed36fcf611793d2a584eaa355bb9598eceb52404039b18");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("53907f6e-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("0b7a8683-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mongo-2390404661-pth19";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.4");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("0b79f58e-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("ff5ae01c-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://6b0797890efdff0b6cf9efc424b7c97983dc11e784fed66afdb4bde52d131e09");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:57c67caab3d8f9ed1fbffe159b10be52e0a0610122c16b3efea50a90ff435584";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mongo";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("0b7a8683-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://8825243d39d3cd2ef04573e92c84af4c88ea2e8bcfed5004e5736e8ef8b52261");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:763176ce519bad61e9e3a03314905c323f217a32f19c8202492207ca02e3ac28";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo-statsd";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/demo-mongo-statsd";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("0b7a8683-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("23771fcc-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mysql-4035395549-63htk";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.6");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("2376acd1-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("ff713842-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://321c894c1f3bd83fcf6653959786335c85582eb4144814667b798543f093c154");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:ec161391b8c32a70b45c4eb505fb94b674a41e7de920a20d37887252e7385d61";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mysql";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("23771fcc-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("17794e97-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "redis-943706705-mmiiv";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.5");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("17787132-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("ff66673d-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://24533babda78b7370d5da9f8bd72f629e5c6074abb77191a17df1fda59b14e7f");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:dd9fe7db52364fb422efadb450d174353003b770a20dccf1ec435acd0600d77b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "redis:2.8.19";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("17794e97-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("2f8770fc-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "wordpress-508242932-vz99d";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "508242932";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "dev";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.7");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff33d569-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("2f86e7ea-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("2f769877-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://9355ce08bf1b56305e2e390e53b1cf277c6cad83a756f167c4b66f1dbb83480e");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:fcb67315d99b058248150d9bac6b25fb24948b45ff1e8c5796174293e19fc6a8";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "wordpress";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("2f8770fc-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("a5b43085-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "cassandra-422472749-3zf02";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "422472749";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "cassandradb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.13");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("a5b3c3cf-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("a585a45c-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://68fa06a45387085cc2c40a9ad058ee779100406de092752fc5cb0d2fdb074f40");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:735763a4db0ae83c58e26337d959ca302e71e8a294279413cb50c014e532f20b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "cassandra";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "cassandra:2.0.16";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("a5b43085-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("e1b44aac-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "client-3814011022-frwih";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3814011022";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "clients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.18");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("e1b3e204-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://821e3676f98d983e737d52e4547dab44d90ac5b5f42ea204df2033bf22dd9c08");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("e1b44aac-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("edbd7d18-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-301449151-0g9qu";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.21");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("edbcefc9-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("edb15e0c-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://22f7b287f4ecce24ef3e0436fb56527a22ea048fbd3cf66f154bb9129e09d163");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("edbd7d18-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("edbd757f-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-301449151-72nr2";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.20");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("edbcefc9-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("edb15e0c-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://7098e98139b95f187e88f8ec87311666813135ba3d5fa93d95d62950f58c5828");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("edbd757f-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("edbd6b0b-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "javaapp-301449151-8ym28";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "301449151";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jfrontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.19");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("edbcefc9-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("bbbbbbbb-2222-bbbb-2222-bbbbbbbbbbbb");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("edb15e0c-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://e6f62cfafac2b67825508452667d7823059f62eb4c8e894861e40ff64dcca922");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:83d9b723dd3401f245fd940695f7f731138bfc1ae5dddc4fae1e0f7b68052d87";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "javaapp";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/counterapp";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("edbd6b0b-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("f9bbb1b3-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "jclient-4183544332-b90rh";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "4183544332";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "jclients";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.22");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("f9bb18e2-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://d4f2ff98ad00f354026149f122419743d8971e2315804161432d8396dc885852");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:a8e04461b233d63ca6c3d977a2407aefadcccf60d4cd4ca239ce91605dd2d969";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "client";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/recurling";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("f9bbb1b3-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("b1b32802-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mongo-2390404661-5acw0";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "2390404661";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mongodb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("172.17.0.14");
		evt.mutable_object()->add_ip_addresses("192.168.1.2");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("b1b2abfc-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("a5935c4b-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://8eb1bf10f5011a7fd406bf4db0c8910aa93a872336d84f46d7515b61aa31e665");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:57c67caab3d8f9ed1fbffe159b10be52e0a0610122c16b3efea50a90ff435584";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mongo";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("b1b32802-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://b29434fbb986953a6d1f226d2a2f135158cb6ab02772a67e709f82cd0de65a68");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:763176ce519bad61e9e3a03314905c323f217a32f19c8202492207ca02e3ac28";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mongo-statsd";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "ltagliamonte/demo-mongo-statsd";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("b1b32802-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("c9abc9e6-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "mysql-4035395549-quosa";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "4035395549";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "mysqldb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.16");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("c9ab5a0c-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("a5a9f5fe-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://0422e3b178b7d959539b7489419a06076507905609760d533e6a78adc43a6e06");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:ec161391b8c32a70b45c4eb505fb94b674a41e7de920a20d37887252e7385d61";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "mysql";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "mysql";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("c9abc9e6-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("bdb0b0dc-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "redis-943706705-hfq7y";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "943706705";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "redisdb";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.15");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("bdafe4b3-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("aaaaaaaa-1111-aaaa-1111-aaaaaaaaaaaa");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("a59f486f-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://c4bc3bf262edb25a1ea03b3e8e981d034349b018afd3c070c53f240177a39541");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:dd9fe7db52364fb422efadb450d174353003b770a20dccf1ec435acd0600d77b";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "redis";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "redis:2.8.19";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("bdb0b0dc-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("k8s_pod");
		evt.mutable_object()->mutable_uid()->set_id("d5b708bf-6c5a-11e7-93f8-d8cb8a319c52");

		(*evt.mutable_object()->mutable_tags())["k8s_pod.name"] = "wordpress-3014601834-kt2fm";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.pod-template-hash"] = "3014601834";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.namespace"] = "prod";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.role"] = "frontend";
		(*evt.mutable_object()->mutable_tags())["k8s_pod.label.app"] = "demo";

		evt.mutable_object()->add_ip_addresses("192.168.1.2");
		evt.mutable_object()->add_ip_addresses("172.17.0.17");

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_namespace");
		parent->set_id("ff42a713-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_replicaset");
		parent->set_id("d5b69872-6c5a-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_node");
		parent->set_id("de2cee4a-6c59-11e7-93f8-d8cb8a319c52");
		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_service");
		parent->set_id("d5a96d55-6c5a-11e7-93f8-d8cb8a319c52");


		m_analyzer->infra_state()->load_single_event(evt);
		evt.Clear();


		evt.set_type(draiosproto::ADDED);
		evt.mutable_object()->mutable_uid()->set_kind("container");
		evt.mutable_object()->mutable_uid()->set_id("docker://04a1484539b44a6112c1bb36540bed59a534439f53b4af747230bab4e308bb22");

		(*evt.mutable_object()->mutable_tags())["container.imageid"] = "docker://sha256:fcb67315d99b058248150d9bac6b25fb24948b45ff1e8c5796174293e19fc6a8";
		(*evt.mutable_object()->mutable_tags())["container.name"] = "wordpress";
		(*evt.mutable_object()->mutable_tags())["container.image"] = "wordpress";

		parent = evt.mutable_object()->mutable_parents()->Add();
		parent->set_kind("k8s_pod");
		parent->set_id("d5b708bf-6c5a-11e7-93f8-d8cb8a319c52");


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
	(*evt->mutable_object()->mutable_tags())["host.hostName"] = "sysdig-cloud-production-collector-i-e2a262d2";
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
	parent->set_id("d5b708bf-6c5a-11e7-93f8-d8cb8a319c52");

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
	cue.mutable_object()->mutable_uid()->set_id("d5b708bf-6c5a-11e7-93f8-d8cb8a319c52");

	is->load_single_event(cue);
	cue.Clear();

	ASSERT_FALSE(is->has(make_pair("k8s_pod", "d5b708bf-6c5a-11e7-93f8-d8cb8a319c52")));
	ASSERT_FALSE(is->has(make_pair("container", 
		"docker://04a1484539b44a6112c1bb36540bed59a534439f53b4af747230bab4e308bb22")));
	ASSERT_EQ(is->get(make_pair("container", 
		"docker://04a1484539b44a6112c1bb36540bed59a534439f53b4af747230bab4e308bb22")), nullptr);
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

	container_id = "docker://22f7b287f4ecce24ef3e0436fb56527a22ea048fbd3cf66f154bb9129e09d163";
	res = is->match_scope(container_id, host_id, p);
	ASSERT_TRUE(res);
	res = is->match_scope(container_id, host_id, p);
	ASSERT_TRUE(res);

	// Test in-agent splitting
	std::vector<std::string> c_ids{
		"docker://c4bc3bf262edb25a1ea03b3e8e981d034349b018afd3c070c53f240177a39541",
		"docker://f7bb4d7358a91e67b0e4a1ebc84403605ad07c2f6f8f5f7b0e5be214c5ba3466"
	};
	std::vector<std::unique_ptr<draiosproto::container_group>> result;
	is->state_of(c_ids, result);

	std::set<std::string> expected_uids{
		"ff42a713-6c59-11e7-93f8-d8cb8a319c52",
		"ff7aec3b-6c59-11e7-93f8-d8cb8a319c52",
		"bdafe4b3-6c5a-11e7-93f8-d8cb8a319c52",
		"a59f486f-6c5a-11e7-93f8-d8cb8a319c52",
		"bdb0b0dc-6c5a-11e7-93f8-d8cb8a319c52",
		"ff33d569-6c59-11e7-93f8-d8cb8a319c52",
		"aaaaaaaa-1111-aaaa-1111-aaaaaaaaaaaa",
		"ff7b9cad-6c59-11e7-93f8-d8cb8a319c52",
		"ff4fb44b-6c59-11e7-93f8-d8cb8a319c52",
		"bdaf5af4-6c5a-11e7-93f8-d8cb8a319c52",
		"de2cee4a-6c59-11e7-93f8-d8cb8a319c52",
		"ff7c8ff7-6c59-11e7-93f8-d8cb8a319c52"
	};
	for(const auto &cg : result) {
		auto it = expected_uids.find(cg->uid().id());
		if (it != expected_uids.end())
			expected_uids.erase(it);
	}

	ASSERT_EQ(result.size(), 12);
	ASSERT_TRUE(expected_uids.empty());
}