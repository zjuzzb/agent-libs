#include "k8s_hpa_store.h"

#include "gtest.h"

class k8s_hpa_store_test : public ::testing::Test
{
protected:
	void SetUp() override
	{
		m_deployment = create_container_group(k8s_hpa_store::DEPLOYMENT_KIND,
		                                      "deployment_uid",
						      "deployment_name",
		                                      "node",
		                                      "namespace",
		                                      {},
		                                      {},
		                                      {});

		m_hpa = create_container_group(k8s_hpa_store::HPA_KIND,
		                               "hpa_uid",
		                               "hpa_name",
		                               "node",
		                               "namespace",
		                               {},
		                               {{"hpa.scale.target.ref.kind", "Deployment"}, {"hpa.scale.target.ref.name", "deployment_name"}},
		                               {});
	}

	draiosproto::container_group create_container_group(const std::string& kind
							    , const std::string& id
							    , const std::string& name
							    , const std::string& node
							    , const std::string& ns
							    , std::map<std::string, std::string>&& labels
							    , std::map<std::string, std::string>&& internal_tags
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

		if(!name.empty())
		{
			std::string prefix;
			if(kind == k8s_hpa_store::DEPLOYMENT_KIND)
			{
				prefix = "kubernetes.deployment.name";
			}
			else if(kind == k8s_hpa_store::HPA_KIND)
			{
				prefix = "kubernetes.hpa.name";
			}
			cg.mutable_tags()->insert({prefix, name});
		}

		for(auto& pair : selectors)
		{
			cg.mutable_selectors()->insert({std::move(pair.first), std::move(pair.second)});
		}

		for(auto& pair : internal_tags)
		{
			cg.mutable_internal_tags()->insert({std::move(pair.first), std::move(pair.second)});
		}

		return cg;
	}

	draiosproto::container_group& get_from_state(const draiosproto::container_group& cg)
	{
		return *m_state[{cg.uid().kind(), cg.uid().id()}].get();
	}

	std::pair<std::string, std::string> get_uid_from_cg(const draiosproto::container_group& cg)
	{
		return {cg.uid().kind(), cg.uid().id()};
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

	void clear_state()
	{
		m_state.clear();
	}
	k8s_hpa_store m_hpa_store;
	k8s_hpa_store::state_t m_state;

	draiosproto::container_group m_deployment;
	draiosproto::container_group m_hpa;
};


TEST_F(k8s_hpa_store_test, handle_add_and_update)
{
	add_container_groups_to_state(m_deployment, m_hpa);

	// Simulate deployment arriving before hpa
	m_hpa_store.handle_add({m_deployment.uid().kind(), m_deployment.uid().id()}, m_state);
	m_hpa_store.handle_add({m_hpa.uid().kind(), m_hpa.uid().id()}, m_state);

	std::size_t hpa_chd_size = get_from_state(m_hpa).children().size();
	EXPECT_EQ(hpa_chd_size, 1) << get_from_state(m_hpa).DebugString() + "\n" + get_from_state(m_deployment).DebugString();

	std::string child_id = get_from_state(m_hpa).children(0).id();
	EXPECT_EQ(child_id, m_deployment.uid().id());

	// Now test the other way round. hpa arrives before deployment
	clear_state();
	m_hpa_store.clear();

	add_container_groups_to_state(m_hpa, m_deployment);
	m_hpa_store.handle_add({m_hpa.uid().kind(), m_hpa.uid().id()}, m_state);
	m_hpa_store.handle_add({m_deployment.uid().kind(), m_deployment.uid().id()}, m_state);

	hpa_chd_size = get_from_state(m_hpa).children().size();
	EXPECT_EQ(hpa_chd_size, 1) << get_from_state(m_hpa).DebugString() + "\n" + get_from_state(m_deployment).DebugString();

	child_id = get_from_state(m_hpa).children(0).id();
	EXPECT_EQ(child_id, m_deployment.uid().id());

	// We expect an update on HPA does non change relationships
	m_hpa_store.handle_update(get_uid_from_cg(m_hpa), m_state);
	hpa_chd_size = get_from_state(m_hpa).children().size();
	EXPECT_EQ(hpa_chd_size, 1) << get_from_state(m_hpa).DebugString() + "\n" + get_from_state(m_deployment).DebugString();

	child_id = get_from_state(m_hpa).children(0).id();
	EXPECT_EQ(child_id, m_deployment.uid().id());

	// Now update the deployment. Also in this case we expect any change
	m_hpa_store.handle_update(get_uid_from_cg(m_hpa), m_state);
	hpa_chd_size = get_from_state(m_hpa).children().size();
	EXPECT_EQ(hpa_chd_size, 1) << get_from_state(m_hpa).DebugString() + "\n" + get_from_state(m_deployment).DebugString();

	child_id = get_from_state(m_hpa).children(0).id();
	EXPECT_EQ(child_id, m_deployment.uid().id());

}

TEST_F(k8s_hpa_store_test, handle_delete)
{
	add_container_groups_to_state(m_deployment, m_hpa);

	// Simulate deployment arriving before hpa
	m_hpa_store.handle_add({m_deployment.uid().kind(), m_deployment.uid().id()}, m_state);
	m_hpa_store.handle_add({m_hpa.uid().kind(), m_hpa.uid().id()}, m_state);

	// Delete the hpa. We expect the hpa object in m_state has no children
	// and that the deployment has no parent
	m_hpa_store.handle_delete(get_uid_from_cg(m_hpa), m_state);

	std::size_t hpa_chd_size = get_from_state(m_hpa).children().size();
	EXPECT_EQ(hpa_chd_size, 0) << get_from_state(m_hpa).DebugString() + "\n" + get_from_state(m_deployment).DebugString();

}

TEST_F(k8s_hpa_store_test, connect_hpa_to_target)
{
	clear_state();
	m_hpa_store.clear();
	add_container_groups_to_state(m_deployment, m_hpa);

	// First case. a target has already arrived
	m_hpa_store.handle_add(get_uid_from_cg(m_deployment), m_state);
	m_hpa_store.connect_hpa_to_target(get_uid_from_cg(m_hpa), m_state);

	// Expect 1 child in hpa
	auto hpa_chd_size = get_from_state(m_hpa).children().size();
	EXPECT_EQ(hpa_chd_size, 1);

	auto hpa_child_id = get_from_state(m_hpa).children(0).id();
	EXPECT_EQ(hpa_child_id, m_deployment.uid().id());

	// Second case. Target is not arrived yet
	clear_state();
	m_hpa_store.clear();
	add_container_groups_to_state(m_hpa);
	m_hpa_store.handle_add(get_uid_from_cg(m_hpa), m_state);

	// We expect the hpa to be added in m_hpa_waiting_for_target
	auto waiting = m_hpa_store.m_hpa_waiting_for_target.size();
	EXPECT_EQ(waiting, 1);

	auto waiting_target = m_hpa_store.m_hpa_waiting_for_target.begin()->first;
	std::pair<std::string, std::string> expected({m_deployment.uid().kind(), "deployment_name"});
	EXPECT_EQ(waiting_target, expected);
}

TEST_F(k8s_hpa_store_test, get_hpa_target_kind_and_name)
{
	auto target = m_hpa_store.get_hpa_target_kind_and_name(m_hpa);
	std::pair<std::string, std::string> expected({k8s_hpa_store::DEPLOYMENT_KIND, "deployment_name"});
	EXPECT_EQ(target, expected);

	draiosproto::container_group m_hpa2(m_hpa);

	// Suppose we get an hpa with invalid ref values
	m_hpa2.mutable_internal_tags()->clear();
	m_hpa2.mutable_internal_tags()->insert({{"hpa.scale.target.ref.kind", "NotScalableType"},
	                                        {"hpa.scale.target.ref.name", "aSillyName"}});

	target = m_hpa_store.get_hpa_target_kind_and_name(m_hpa2);
	expected = {"", "aSillyName"};
	EXPECT_EQ(target, expected);
}
