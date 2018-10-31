#include <gtest.h>
#include <infrastructure_state.h>

class inf_state_test : public testing::Test
{
public:
	using uid_t = infrastructure_state::uid_t;
	using cue_t = draiosproto::congroup_update_event;
	inf_state_test()
	{
		m_sinsp.reset(new sinsp());
		m_infra_state.reset(new infrastructure_state(ORCHESTRATOR_EVENTS_POLL_INTERVAL, m_sinsp.get(), "/opt/draios"));
	}
       	
protected:
	virtual void SetUp() override
	{
		ASSERT_NE(m_infra_state.get(), nullptr);
		ASSERT_TRUE(m_infra_state.get()->inited());
	}
	

	bool has_congroup(const std::string cg_kind, const std::string cg_id) const
	{
		return m_infra_state->has(make_pair(cg_kind, cg_id));
	}

	bool has_congroup(const uid_t& key) const
	{
		return m_infra_state->has(key);
	}
	
	bool has_congroup(const draiosproto::congroup_uid& key) const
	{
		uid_t cg = make_pair(key.kind(), key.id());
		return m_infra_state->has(cg);
	}

	cue_t add_congroup(const std::string& kind) {
		cue_t cue;

		std::string id = kind + to_string(++m_map_of_counts[kind]);
		// Add Entity
		cue.set_type(draiosproto::ADDED);
		cue.mutable_object()->mutable_uid()->set_kind(kind);
		cue.mutable_object()->mutable_uid()->set_id(id);
		
		m_infra_state->load_single_event(cue);

		if(kind == "container") {
			m_containers.push_back(id);
		}
		return cue;
	}

	void add_parent_link(cue_t& child, const cue_t& parent) {

		child.set_type(draiosproto::UPDATED);
		auto par = child.mutable_object()->mutable_parents()->Add();
		par->set_kind(parent.object().uid().kind());
		par->set_id(parent.object().uid().id());

		m_infra_state->load_single_event(child);
	}
	
	void remove_congroup(cue_t& cue) {
		cue.set_type(draiosproto::REMOVED);
		m_infra_state->load_single_event(cue);

		if(cue.object().uid().kind() == "container") {
			for(auto it = m_containers.begin(); it != m_containers.end(); it++)
			{
				if(*it == cue.object().uid().id()) {
					m_containers.erase(it);
					break;
				}
			}
		}

		// We don't want this object to be used
		// Make sure of it.
		cue.Clear();
	}
	
	void print_result(const container_groups& result) const {
		std::cout << " ==== Results Begin ====== " << std::endl;
		for(const auto& cg : result) {
			std::cout << "Kind: " << cg.uid().kind() << " Id: " << cg.uid().id() << std::endl; 
		}
		std::cout << " ==== Results End ====== " << std::endl << std::endl;
	}

	std::unique_ptr<infrastructure_state> m_infra_state;
	std::unique_ptr<sinsp> m_sinsp;
	std::unordered_map<std::string, int> m_map_of_counts;
	std::vector<std::string> m_containers;
};

TEST_F(inf_state_test, EmptyStateTest)
{	
	ASSERT_NE(m_infra_state.get(), nullptr);

	// Test empty Infrastructure State
	// returns false for any key test
	uid_t cont = make_pair("container","123");
	ASSERT_FALSE(has_congroup(cont));
	ASSERT_FALSE(has_congroup("k8s_pod","234"));

	// Initially, when we ping the infra state for its current state
	// "result" should always be empty
	container_groups result;
	m_infra_state->state_of(m_containers, &result );
	ASSERT_TRUE(result.empty());

	// Test with get_state also
	m_infra_state->get_state( &result );
	ASSERT_TRUE(result.empty());	
}

TEST_F(inf_state_test, AddCongroupTest)
{
	// Add a few congroups and test for presence
	auto cont = add_congroup("container");
	auto pod  = add_congroup("k8s_pod");

	ASSERT_TRUE(has_congroup(cont.object().uid()));
	ASSERT_TRUE(has_congroup(pod.object().uid()));
	ASSERT_EQ(m_infra_state->size(),2);
}

TEST_F(inf_state_test, AlwaysReturnNodeTypes)
{
	// If there is a k8s_node type congroup
	// always return it. Even if we don't have
	// a namespace parent for it.

	// Add a node
	auto node1 = add_congroup("k8s_node");
	
	container_groups result;
	m_infra_state->get_state(&result);

	ASSERT_FALSE(result.empty());
	ASSERT_EQ(result.size(),1);
	result.Clear();

	// Add another node
	auto node2 = add_congroup("k8s_node");
	m_infra_state->get_state(&result);

	ASSERT_FALSE(result.empty());
	ASSERT_EQ(result.size(),2);
}

TEST_F(inf_state_test, DontExportPodsWithoutNodeParents)
{
	// All entities except nodes must have namespace parents.
	// But pods must additionally have node parents

	// Result of pinging InfraState
	container_groups result;

	// Add Pod1
	auto pod1 = add_congroup("k8s_pod");

	// Add a namespace
	auto ns1 = add_congroup("k8s_namespace");

	// Make namespace1 parent of pod1
	add_parent_link(pod1, ns1);

	// Now get infra state
	m_infra_state->get_state(&result);
	// Result should ONLY contain namespace
	// Not pod
	ASSERT_EQ(result.size(),1);
	result.Clear();

	// Now add a node
	auto node1 = add_congroup("k8s_node");
	// Now get infra state
	m_infra_state->get_state( &result);
	// Result should ONLY contain namespace and node
	// Not pod
	ASSERT_EQ(result.size(),2);
	result.Clear();

	// Now finally add node as parent of pod
	add_parent_link(pod1, node1);

	// Verify with get_state
	m_infra_state->get_state(&result);
	// Result should contain all 3 
	ASSERT_EQ(result.size(),3);
	result.Clear();
}

TEST_F(inf_state_test, CongroupsWithoutNamespaceParentsTest)
{
	// MAIN TEST Which tests if congroup entities
	// show up ONLY if they have namespace parents
	// Result of pinging InfraState
	container_groups result;

	// Add a couple of congroup entities.
	// Pods, services etc.

	// Add container1
	auto cont1 = add_congroup("container");
	// Add container2
	auto cont2 = add_congroup("container");
	// Pods 1
	auto pod1 = add_congroup("k8s_pod");
	// Add k8s_pod2
	auto pod2 = add_congroup("k8s_pod");

	// The internal map should have 4 items:
	// 2 pods, 2 containers
	ASSERT_EQ(m_infra_state->size(),4);
     
	// Make Pod1 parent of container 1
	add_parent_link(cont1, pod1);
	
	// Make Pod2 parent of container 2
	add_parent_link(cont2, pod2);

	// Now ping infra result - should show up empty
	m_infra_state->state_of(m_containers, &result);

	ASSERT_TRUE(result.empty());

	// Now add a namespace and test it shows up
	// along with the pods which are now its children
	auto ns1 = add_congroup("k8s_namespace");

	ASSERT_EQ(m_infra_state->size(),5);

	// Make namespace1 parent of pod1
	add_parent_link(pod1, ns1);
	
	// Make namespace1 parent of pod2 
	add_parent_link(pod2, ns1);

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should not be empty
	ASSERT_FALSE(result.empty());
	// We should have 1 entity. 1 namespace only
	// The pods should not show up because of no node
	// parent
	ASSERT_EQ(result.size(), 1);
	result.Clear();

	// See if get_state shows same results
	m_infra_state->get_state(&result);
	ASSERT_EQ(result.size(), 1);
	result.Clear();

	// Now add a node and make it parents of pods
	auto node1 = add_congroup("k8s_node");
	add_parent_link(pod1, node1);
	add_parent_link(pod2, node1);

	// See if get_state shows updated results
	m_infra_state->get_state(&result);
	// We should have:
	// 2 pods, 1 Namespace, 1 node
	ASSERT_EQ(result.size(), 4);
	result.Clear();

	// Now remove the namespace and verify no pod results show up
	remove_congroup(ns1);
	
	// Verify it is gone
	ASSERT_FALSE(has_congroup(ns1.object().uid()));

	// Now get infra state
	m_infra_state->get_state( &result);

	// Now result should have only Node result
	ASSERT_EQ(result.size(), 1);
}

TEST_F(inf_state_test, NamespacesWithoutContainersTest)
{
	// Result of pinging InfraState
	container_groups result;

	// Add a namespace
	auto ns1 = add_congroup("k8s_namespace");

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should be empty
	ASSERT_TRUE(result.empty());

	// Add a pod
	auto pod1 = add_congroup("k8s_pod");
	// Make it a child of the namespace
	add_parent_link(pod1, ns1);

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should still be empty (since no containers)
	ASSERT_TRUE(result.empty());

	// Now add a container
	auto cont1 = add_congroup("container");
	// Make it a child of the pod.
	add_parent_link(cont1, pod1);

	// Now the namespace alone should show up
	m_infra_state->state_of(m_containers, &result);
	ASSERT_EQ(result.size(),1);
	result.Clear();

	// Now add a node and verify even the pod shows up
	auto node1 = add_congroup("k8s_node");
	add_parent_link(pod1, node1);

	// Now the namespace, node, pod should show up
	m_infra_state->state_of(m_containers, &result);
	ASSERT_EQ(result.size(),3);
	result.Clear();
	
	// Now remove the pod and see the result
	remove_congroup(pod1);
	m_infra_state->state_of(m_containers, &result);
	// With the Pod removed, the container has
	// no parents; so no results show up
	ASSERT_EQ(result.size(), 0);
}

TEST_F(inf_state_test, ComprehensiveTest)
{
	// This will be a comprehensive Test With Containers,
	// Pods, Deployments, Services, Nodes, ReplicaSets etc.
	// Test the dynamic structure of the infrastructure state
	// as you add and remove congroups

	// Create 3 containers to start of with
	auto cont1 = add_congroup("container");
	auto cont2 = add_congroup("container");
	auto cont3 = add_congroup("container");

	// Add 3 pods and assign a container to each pod
	auto pod1 = add_congroup("k8s_pod");
	auto pod2 = add_congroup("k8s_pod");
	auto pod3 = add_congroup("k8s_pod");

	add_parent_link(cont1, pod1);
	add_parent_link(cont2, pod2);
	add_parent_link(cont3, pod3);

	// add node
	auto node1 = add_congroup("k8s_node");
	add_parent_link(pod1, node1);
	add_parent_link(pod2, node1);
	add_parent_link(pod3, node1);

	// Add 2 namespaces
	auto ns1 = add_congroup("k8s_namespace");
	auto ns2 = add_congroup("k8s_namespace");

	// Add a replica set
	auto rs1 = add_congroup("k8s_replicaset");

	// Add a service
	auto serv1 = add_congroup("k8s_service");

	// Add a deployment
	auto dep1 = add_congroup("k8s_deployment");

	// Now form frame work of connections:
	add_parent_link(pod1 , rs1);
	add_parent_link(pod2, rs1);
	add_parent_link(pod3 , serv1);
	add_parent_link(pod1, serv1);
	add_parent_link(pod2, dep1);

	// Result of pinging InfraState
	container_groups result;
	m_infra_state->state_of(m_containers, &result);
	// Since no congroups have namespaces as parents, this
	// should return just 1 (the node)
	ASSERT_EQ(result.size(), 1);
	result.Clear();

	// Add namespaces to all entities as parent links
	add_parent_link(pod1 , ns1);
	add_parent_link(pod2, ns1);
	add_parent_link(pod3 , ns2);
	add_parent_link(serv1 ,  ns2);
	add_parent_link(rs1, ns1);
	add_parent_link(dep1, ns2);

	m_infra_state->state_of(m_containers, &result);
	// All entities have namespace parents;
	// this should return size 9
	ASSERT_EQ(result.size(), 9);
	result.Clear();

	// Verify if get_state shows same results
	m_infra_state->get_state(&result);
	// This should return size 9
	ASSERT_EQ(result.size(), 9);
	result.Clear();

	// Get state of only 1 container
	// and see if this returns lesser size
	// than get_state
	// This simulates delegated agents
	std::vector<string> single_cont(m_containers.begin(), m_containers.begin()+1);
	m_infra_state->state_of(single_cont, &result);
	ASSERT_EQ(result.size(), 6);
	result.Clear();

	// remove one container and see the results
	ASSERT_EQ(m_containers.size(),3); // before
	remove_congroup(cont1);
	ASSERT_EQ(m_containers.size(),2); // after
	m_infra_state->state_of(m_containers, &result);
	// We should not see the pod1 in results
	// This is because it is parent of cont1
	ASSERT_EQ(result.size(), 8);
	result.Clear();

	// Verify if get_state shows all results
	m_infra_state->get_state(&result);
	// This should return size 9 (like before)
	ASSERT_EQ(result.size(), 9);
	result.Clear();
}
