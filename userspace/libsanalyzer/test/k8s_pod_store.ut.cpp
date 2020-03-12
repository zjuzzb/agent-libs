#include "k8s_pod_store.h"
#include <memory>


#include <gtest.h>

class k8s_pod_store_test : public ::testing::Test
{
protected:
	k8s_pod_store_test()
	{

	}

	~k8s_pod_store_test()
	{

	}

	void SetUp() override
	{
		m_pod = create_container_group(k8s_pod_store::POD_KIND
						  , "1"
						  , "node"
						  , "namespace"
						  , {{".label.key1", "val1"}, {".label.key2", "val2"}, {".label.key3", "val3"}},
						  {});

		m_service =  create_container_group(k8s_pod_store::SERVICE_KIND
						       , "2"
						       , "node"
						       , "namespace"
						       , {}
						       , {{"key1", "val1"}, {"key2", "val2"}});

		m_service_in_another_ns = create_container_group(k8s_pod_store::SERVICE_KIND
								    , "3"
								    , "node"
								    , "namespace2"
								    , {}
								    , {{"key1", "val1"}, {"key2", "val2"}});

		m_node = create_container_group(k8s_pod_store::NODE_KIND, "4", "node", "", {}, {});

	}

	draiosproto::container_group create_container_group(const std::string& kind
							    , const std::string& id
							    , const std::string& node
							    , const std::string& ns
							    , std::map<std::string, std::string>&& labels
							    , std::map<std::string, std::string>&& selectors) const
	{
		draiosproto::container_group cg;
		cg.mutable_uid()->set_id(id);
		cg.mutable_uid()->set_kind(kind);
		cg.set_node(node);
		cg.set_namespace_(ns);

		for(auto& pair : labels)
		{
			cg.mutable_tags()->insert({std::move(pair.first), std::move(pair.second)});
		}

		for(auto& pair : selectors)
		{
			cg.mutable_selectors()->insert({std::move(pair.first), std::move(pair.second)});
		}

		return cg;
	}


	template<typename ...Args>
	void add_container_groups_to_state(Args ...args);

	template<typename First, typename... Others>
	typename std::enable_if<std::is_same<First, draiosproto::container_group>::value, void>::type
	add_container_groups_to_state(const First& first, Others... others)
	{
		add_container_groups_to_state(first);
		add_container_groups_to_state(others...);
	}

	template<typename C>
	typename std::enable_if<std::is_same<C, draiosproto::container_group>::value, void>::type
	add_container_groups_to_state(const C& cg)
	{
		m_state[{cg.uid().kind(), cg.uid().id()}] = std::unique_ptr<draiosproto::container_group>(new draiosproto::container_group(cg));
	}

	template<typename ...Args>
	void handle_many_add(Args ...args);

	template<typename F, typename ...Others>
	typename std::enable_if<std::is_same<F, draiosproto::container_group>::value, void>::type
	handle_many_add(const F& f, Others ...others)
	{
		handle_many_add(f);
		handle_many_add(others...);
	}

	template<typename F>
	typename std::enable_if<std::is_same<F, draiosproto::container_group>::value, void>::type
	handle_many_add(const F& cg)
	{
		m_pod_store.handle_add({cg.uid().kind(), cg.uid().id()}, m_state);
	}

	std::string get_pod_parent_by_kind(const draiosproto::container_group& cg, std::string kind) const
	{
		std::string ret;

		for(const auto& parent : cg.parents())
		{
			if(parent.kind() == kind)
			{
				ret = parent.id();
				break;
			}
		}
		return ret;
	}

	void clear_state()
	{
		m_state.clear();
	}

	k8s_pod_store m_pod_store;
	k8s_pod_store::state_t m_state;

	draiosproto::container_group m_pod;
	draiosproto::container_group m_service;
	draiosproto::container_group m_service_in_another_ns;
	draiosproto::container_group m_node;
};

TEST_F(k8s_pod_store_test, handle_add)
{
	// Add a service and matching pod
	clear_state();

	add_container_groups_to_state(m_pod, m_service, m_service_in_another_ns, m_node);

	// Simualte that the services arrives before the pod
	handle_many_add(m_service, m_service_in_another_ns, m_pod, m_node);

	std::size_t pod_parent_size = m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}]->parents().size();
	EXPECT_EQ(pod_parent_size, 2) << m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}].get()->DebugString();

        std::string service_parent_id = get_pod_parent_by_kind(*m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}].get(), k8s_pod_store::SERVICE_KIND);
	EXPECT_EQ(service_parent_id, m_service.uid().id());

	std::string node_parent_id = get_pod_parent_by_kind(*m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}].get(), k8s_pod_store::NODE_KIND);
	EXPECT_EQ(node_parent_id, m_node.uid().id());

	std::size_t service_children_size = m_state[{m_service.uid().kind(), m_service.uid().id()}]->children().size();
	EXPECT_EQ(service_children_size, 1) << m_state[{m_service.uid().kind(), m_service.uid().id()}]->DebugString();

	// Simulate the pod arrived before the services
	m_pod_store.clear();
	clear_state();

	add_container_groups_to_state(m_pod, m_service, m_service_in_another_ns, m_node);
	handle_many_add(m_pod, m_service, m_service_in_another_ns, m_node);

	pod_parent_size = m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}]->parents().size();
	EXPECT_EQ(pod_parent_size, 2);

        service_parent_id = m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}]->parents(0).id();
	EXPECT_EQ(service_parent_id, m_service.uid().id());

	node_parent_id = m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}]->parents(1).id();
	EXPECT_EQ(node_parent_id, m_node.uid().id());

	// Simulate the node arrived before the pod
	m_pod_store.clear();
	clear_state();

	add_container_groups_to_state(m_pod, m_service, m_service_in_another_ns, m_node);
	handle_many_add(m_node, m_pod, m_service, m_service_in_another_ns);

	pod_parent_size = m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}]->parents().size();
	EXPECT_EQ(pod_parent_size, 2);

        service_parent_id = get_pod_parent_by_kind(*m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}].get(), k8s_pod_store::SERVICE_KIND);
	EXPECT_EQ(service_parent_id, m_service.uid().id());

	node_parent_id = service_parent_id = get_pod_parent_by_kind(*m_state[{k8s_pod_store::POD_KIND, m_pod.uid().id()}].get(), k8s_pod_store::NODE_KIND);
	EXPECT_EQ(node_parent_id, m_node.uid().id());
}

TEST_F(k8s_pod_store_test, handle_update)
{
	m_pod_store.clear();
	clear_state();

	add_container_groups_to_state(m_pod, m_service);
	handle_many_add(m_pod, m_service);

	//Now the pod has a service parent.
	//Lets's change the service in a way it no longer matches the pod
	//and ensure the pod no longer has it as a parent

	m_state[{m_service.uid().kind(), m_service.uid().id()}]->mutable_selectors()->clear();
	m_state[{m_service.uid().kind(), m_service.uid().id()}]->mutable_selectors()->insert({{"aaa", "bbb"}, {"ccc", "dddd"}, {"eeee", "ffff"}});

	m_pod_store.handle_update({m_service.uid().kind(), m_service.uid().id()}, m_state);

	//Check that pod has no parents
	std::size_t parent_size = m_state[{m_pod.uid().kind(), m_pod.uid().id()}]->parents().size();
	EXPECT_EQ(parent_size, 0);

	// Now test the other way round. Pod labels change
	m_pod_store.clear();
	clear_state();

	add_container_groups_to_state(m_pod, m_service);
	handle_many_add(m_pod, m_service);

	m_state[{m_pod.uid().kind(), m_pod.uid().id()}]->mutable_tags()->erase(".label.key1");
	m_pod_store.handle_update({m_pod.uid().kind(), m_pod.uid().id()}, m_state);

	parent_size = m_state[{m_pod.uid().kind(), m_pod.uid().id()}]->parents().size();
	EXPECT_EQ(parent_size, 0) << m_state[{m_pod.uid().kind(), m_pod.uid().id()}]->DebugString();
}

TEST_F(k8s_pod_store_test, handle_delete)
{
	m_pod_store.clear();
	clear_state();

	add_container_groups_to_state(m_pod, m_service);
	handle_many_add(m_pod, m_service);

	// Now pod has a parent and service has a child
	// Delete the service and check that pod has no parent
	m_pod_store.handle_delete({m_service.uid().kind(), m_service.uid().id()}, m_state);

	std::size_t pod_parents_size = m_state[{m_pod.uid().kind(), m_pod.uid().id()}]->parents().size();
	EXPECT_EQ(pod_parents_size, 0);

	// Let's do the other way round. Remove the pod
	// and check that the service has no children
	m_pod_store.clear();
	clear_state();

	add_container_groups_to_state(m_pod, m_service);
	handle_many_add(m_pod, m_service);

	m_pod_store.handle_delete({m_pod.uid().kind(), m_pod.uid().id()}, m_state);

	std::size_t service_children_size = m_state[{m_service.uid().kind(), m_service.uid().id()}]->children().size();

	EXPECT_EQ(service_children_size, 0) << m_state[{m_service.uid().kind(), m_service.uid().id()}]->DebugString();
}


TEST_F(k8s_pod_store_test, search_pod_service_parent)
{
	m_pod_store.clear();

	m_pod_store.m_services.emplace(std::make_pair("1", k8s_pod_store::service("2", "default", {{"key1", "val1"}, {"key2", "val2"}})));

	m_pod_store.m_pods.emplace(std::make_pair(
					   "2",
					   k8s_pod_store::pod("2", "default", "node", {{"key1", "val1"}, {"key2", "val2"}}, {})));

	auto srv_id = m_pod_store.search_for_pod_parent_service("2");

	EXPECT_EQ(srv_id, "1");

	// Insert a non matching pod
	m_pod_store.m_pods.emplace(std::make_pair(
					   "2",
					   k8s_pod_store::pod("3", "default", "node", {{"key1", "val10000"}, {"key2", "val20000"}}, {})));


	srv_id = m_pod_store.search_for_pod_parent_service("3");
	EXPECT_EQ(srv_id, "");
}


TEST_F(k8s_pod_store_test, get_labels_from_cg)
{
	draiosproto::container_group cg;

	cg.mutable_tags()->insert({{".label.key1", "val1"}, {".label.key2", "val2"}, {"iecasi", "iecasi"}});

	auto labels = m_pod_store.get_labels_from_cg(cg);

	EXPECT_EQ(labels.size(), 2);

	k8s_pod_store::label_set_t expected({{"key1", "val1"}, {"key2", "val2"}});
	EXPECT_EQ(labels, expected);
}

TEST_F(k8s_pod_store_test, resolve_ports)
{
	m_pod_store.clear();
	clear_state();

	// Add some ports to m_pod
	draiosproto::container_group pod_with_ports(m_pod);
	auto port = pod_with_ports.mutable_ports()->Add();
	port->set_name("ilmionome");
	port->set_target_port(12345);

	draiosproto::container_group service(m_service);
	service.mutable_ports()->Add()->set_name("ilmionome");

	add_container_groups_to_state(pod_with_ports, service);
	m_pod_store.handle_add({pod_with_ports.uid().kind(), pod_with_ports.uid().id()}, m_state);
	// m_pod_store.handle_add({service.uid().kind(), service.uid().id()}, m_state);

	m_pod_store.resolve_ports(service, {pod_with_ports.uid().id()});

	auto srv_port = service.ports(0).target_port();
	EXPECT_EQ(srv_port, 12345) << service.DebugString();
}
