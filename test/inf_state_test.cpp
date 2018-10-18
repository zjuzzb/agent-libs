#include <gtest.h>
#include <infrastructure_state.h>

class inf_state_test : public testing::Test
{
public:
	using uid_t = infrastructure_state::uid_t;
	inf_state_test()
	{
		m_sinsp.reset(new sinsp());
	}
       	
protected:
	virtual void SetUp()
	{
		// Set up
		
	}
	virtual void TearDown()
	{
		// Tear down
	
	}
	virtual void initPtr()
	{
		m_infra_state.reset(new infrastructure_state(ORCHESTRATOR_EVENTS_POLL_INTERVAL,m_sinsp.get(), "/opt/draios"));
		
	}

	bool hasCongroup(std::string cgKind, std::string cgId)
	{
		return m_infra_state->has(make_pair(cgKind, cgId));
	}
	bool hasCongroup(uid_t key)
	{
		return m_infra_state->has(key);
	}

	bool addCongroup(uid_t key)
	{
		return m_infra_state->add(key);
	}
	
	std::unique_ptr<infrastructure_state> m_infra_state;
	std::unique_ptr<sinsp> m_sinsp;
};

class inf_state_test_inited : public inf_state_test
{
protected:
	virtual void SetUp() override
	{
		inf_state_test::initPtr();
       	}
 };

class inf_state_test_with_containers : public inf_state_test_inited
{
protected:
	virtual void SetUp() override
	{
		inf_state_test_inited::SetUp();
		// Future setup that might be
		// needed. 
	}

	uid_t addCongroup(const std::string& kind) {
		draiosproto::congroup_update_event cue;

		std::string id = kind + to_string(++m_map_of_counts[kind]);
		// Add Entity
		cue.set_type(draiosproto::ADDED);
		cue.mutable_object()->mutable_uid()->set_kind(kind);
		cue.mutable_object()->mutable_uid()->set_id(id);
		(*cue.mutable_object()->mutable_tags())[kind+".name"] = id;
		m_infra_state->load_single_event(cue);
		cue.Clear();

		if(kind == "container") {
			m_containers.push_back(id);
		}
		return make_pair(kind,id);
	}

	/*
	void addCongroup(std::string kind, int id) {
		
	}
	*/
	void removeCongroup(const uid_t& key) {
		draiosproto::congroup_update_event cue;
		// Remove Congroup
		cue.set_type(draiosproto::REMOVED);
		cue.mutable_object()->mutable_uid()->set_kind(key.first);
		cue.mutable_object()->mutable_uid()->set_id(key.second);
		m_infra_state->load_single_event(cue);
		cue.Clear();

		if(key.first == "container") {
			for(auto it = m_containers.begin(); it != m_containers.end(); it++)
			{
				if(*it == key.second) {
					m_containers.erase(it);
					break;
				}
			}
		}
	}
	
	void printResult(const container_groups& result) {
		std::cout << " ==== Results Begin ====== " << std::endl;
		for(const auto& cg : result) {
			std::cout << "Kind: " << cg.uid().kind() << " Id: " << cg.uid().id() << std::endl; 
		}
		std::cout << " ==== Results End ====== " << std::endl << std::endl;
	}
	
	std::unordered_map<std::string, int> m_map_of_counts;
	std::vector<std::string> m_containers;
};

TEST_F(inf_state_test, NullptrTest)
{
	// Test that without init, we have a nullptr	
	ASSERT_EQ(m_infra_state.get(), nullptr);
}

TEST_F(inf_state_test, InitTest)
{
	// Test after init all pointers are set up	
	ASSERT_EQ(m_infra_state.get(), nullptr);
	initPtr();
	ASSERT_NE(m_infra_state.get(), nullptr);
	ASSERT_TRUE(m_infra_state.get()->inited());
}

TEST_F(inf_state_test_inited, EmptyStateTest)
{	
	ASSERT_NE(m_infra_state.get(), nullptr);

	// Test empty Infrastructure State
	// returns false for any key test
	uid_t cont = make_pair("container","123");
	ASSERT_FALSE(hasCongroup(cont));
	ASSERT_FALSE(hasCongroup("k8s_pod","234"));
}

TEST_F(inf_state_test_inited, AddCongroupTest)
{
	uid_t cont = make_pair("container","123");
	uid_t pod  = make_pair("k8s_pod", "345");

	// Add it and test for presence
	ASSERT_TRUE(addCongroup(cont));
	ASSERT_TRUE(addCongroup(pod));
	ASSERT_TRUE(hasCongroup(cont));
	ASSERT_TRUE(hasCongroup(pod));
	ASSERT_EQ(m_infra_state->size(),2);
}

TEST_F(inf_state_test_with_containers, TestInfStateWhenEmpty)
{
	// Initially, when we ping the infra state for its current state
	// "result" should always be empty
	container_groups result;
	m_infra_state->state_of(m_containers, &result );

	ASSERT_TRUE(result.empty());
}

TEST_F(inf_state_test_with_containers, CongroupsWithoutNamespaceParentsTest)
{
	// MAIN TEST Which tests if congroup entities
	// show up ONLY if they have namespace parents
	
	draiosproto::congroup_update_event cue;

	// Result of pinging InfraState
	container_groups result;

	// Add a couple of congroup entities.
	// Pods, services etc.

	// Add container1
	auto cont1 = addCongroup("container");
	// Add container2
	auto cont2 = addCongroup("container");
	// Pods 1
	auto pod1 = addCongroup("k8s_pod");
	// Add k8s_pod2
	auto pod2 = addCongroup("k8s_pod");

	// The internal map should have 4 items:
	// 2 pods, 2 containers
	ASSERT_EQ(m_infra_state->size(),4);
     
	// Make Pod1 parent of container 1
	m_infra_state->add_parent_link(cont1, pod1);
	
	// Make Pod2 parent of container 2
	m_infra_state->add_parent_link(cont2, pod2);

	// Now ping infra result - should show up empty
	m_infra_state->state_of(m_containers, &result);

	ASSERT_TRUE(result.empty());

	// Now add a namespace and test it shows up
	// along with the pods which are now its children
	auto ns1 = addCongroup("k8s_namespace");

	ASSERT_EQ(m_infra_state->size(),5);

	// Make namespace1 parent of pod1
	m_infra_state->add_parent_link(pod1, ns1);
	
	// Make namespace1 parent of pod2 
	m_infra_state->add_parent_link(pod2, ns1);

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should not be empty
	ASSERT_FALSE(result.empty());
	// We should have 3 entites. 2 pods and 1 namespace
	ASSERT_EQ(result.size(), 3);

	// Print the results vector:
	printResult(result);	
	result.Clear();

	// See if get_state shows same results
	m_infra_state->get_state(&result);
	ASSERT_EQ(result.size(), 3);
	// Print the results vector:
	printResult(result);	
	result.Clear();

	// Now remove the namespace and verify no results show up
	removeCongroup(ns1);
	
	// Verify it is gone
	ASSERT_FALSE(hasCongroup(ns1));

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should be empty
	ASSERT_TRUE(result.empty());
}

TEST_F(inf_state_test_with_containers, NamespacesWithoutContainersTest)
{
	// Result of pinging InfraState
	container_groups result;

	// Add a namespace
	auto ns1 = addCongroup("k8s_namespace");

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should be empty
	ASSERT_TRUE(result.empty());

	// Add a pod
	auto pod1 = addCongroup("k8s_pod");
	// Make it a child of the namespace
	m_infra_state->add_parent_link(pod1, ns1);

	// Now get infra state
	m_infra_state->state_of(m_containers, &result);

	// Now result should still be empty (since no containers)
	ASSERT_TRUE(result.empty());

	// Now add a container
	// Only adding a container should trigger
	// a valid return for "state_of"
	auto cont1 = addCongroup("container");
	// Make it a child of the pod.
	m_infra_state->add_parent_link(cont1, pod1);

	// Now the pod and namespace should show up
	m_infra_state->state_of(m_containers, &result);
	ASSERT_EQ(result.size(),2);

	result.Clear();
	
	// Now remove the pod and see the result
	removeCongroup(pod1);
	m_infra_state->state_of(m_containers, &result);
	// With the Pod removed, the container has
	// no parents; so no results show up
	ASSERT_EQ(result.size(), 0);
	
}

TEST_F(inf_state_test_with_containers, ComprehensiveTest)
{
	// This will be a comprehensive Test With Containers,
	// Pods, Deployments, Services, Nodes, ReplicaSets etc.
	// Test the dynamic structure of the infrastructure state
	// as you add and remove congroups

	// Create 3 containers to start of with
	auto cont1 = addCongroup("container");
	auto cont2 = addCongroup("container");
	auto cont3 = addCongroup("container");

	// Add 3 pods and assign a container to each pod
	auto pod1 = addCongroup("k8s_pod");
	auto pod2 = addCongroup("k8s_pod");
	auto pod3 = addCongroup("k8s_pod");

	m_infra_state->add_parent_link(cont1, pod1);
	m_infra_state->add_parent_link(cont2, pod2);
	m_infra_state->add_parent_link(cont3, pod3);

	// Add 2 namespaces
	auto ns1 = addCongroup("k8s_namespace");
	auto ns2 = addCongroup("k8s_namespace");

	// Add a replica set
	auto rs1 = addCongroup("k8s_replicaset");

	// Add a service
	auto serv1 = addCongroup("k8s_service");

	// Add a deployment
	auto dep1 = addCongroup("k8s_deployment");

	// Now form frame work of connections:
	m_infra_state->add_parent_link(pod1 , rs1);
	m_infra_state->add_parent_link(pod2, rs1);
	m_infra_state->add_parent_link(pod3 , serv1);
	m_infra_state->add_parent_link(pod1, serv1);
	m_infra_state->add_parent_link(pod2, dep1);

	// Result of pinging InfraState
	container_groups result;
	m_infra_state->state_of(m_containers, &result);
	// Since no congroups have namespaces as parents, this
	// should return empty
	ASSERT_EQ(result.size(), 0);

	// Add namespaces to all entities as parent links
	m_infra_state->add_parent_link(pod1 , ns1);
	m_infra_state->add_parent_link(pod2, ns1);
	m_infra_state->add_parent_link(pod3 , ns2);
	m_infra_state->add_parent_link(serv1 ,  ns2);
	m_infra_state->add_parent_link(rs1, ns1);
	m_infra_state->add_parent_link(dep1, ns2);

	m_infra_state->state_of(m_containers, &result);
	// All entities have namespace parents;
	// this should return size 8
	ASSERT_EQ(result.size(), 8);
	printResult(result);
	result.Clear();

	// Verify if get_state shows same results
	m_infra_state->get_state(&result);
	// This should return size 8
	ASSERT_EQ(result.size(), 8);
	printResult(result);
	result.Clear();

	// remove one namespace and see the results
	removeCongroup(ns2);
	m_infra_state->state_of(m_containers, &result);
	ASSERT_EQ(result.size(), 4);
	printResult(result);
	result.Clear();
}
