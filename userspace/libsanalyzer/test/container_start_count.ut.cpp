#include "container_start_count.h"
#include "analyzer_utils.h"
#include <gtest.h>

class container_start_count_test : public testing::Test
{
public:
	container_start_count_test(){
		machine_id = std::string("test_machine_id");
		m_container_start_count = make_unique<container_start_count>(
			std::bind(&container_start_count_test::get_machine_id,
				  this));
	}

	void add_container(const sinsp_container_info& container_info) {
		m_container_start_count->on_new_container(container_info, nullptr);
	}
		
	const std::string& get_machine_id() {
		return machine_id;
	}
protected:
	std::unique_ptr<container_start_count> m_container_start_count;
	std::string machine_id;
       
};

TEST_F(container_start_count_test, test_all_scenarios)
{
	sinsp_container_info c_info;

	// Verify it is not a pod - sandbox - default option
	ASSERT_FALSE(c_info.is_pod_sandbox());

	// Now make it a podsandbox
	c_info.m_is_pod_sandbox = true;
	ASSERT_TRUE(c_info.is_pod_sandbox());

	// Add this container and verify that we don't add it
	// to our container-start-count
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 0);

	// Now make this a non-podsandbox, but set flag to failed and verify
	c_info.m_lookup_state = sinsp_container_lookup_state::FAILED;
	ASSERT_FALSE(c_info.is_successful());
	c_info.m_is_pod_sandbox = false;
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 0);

	// Now make it successful and not a podsandbox
	c_info.m_lookup_state = sinsp_container_lookup_state::SUCCESSFUL;
	// But make its created time to some time before this class
	// was created. Let's make it zero to be absolutely effective
	c_info.m_created_time = 0;
	// Since this container was created before our container_start_count
	// We should not count this container
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 0);
	
	// Now set a proper time stamp and verify it gets added
	c_info.m_created_time = static_cast<int64_t>(get_epoch_utc_seconds_now());
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 1);
	
	// now add a container with k8s namespace label and verify if it gets added
	std::string ns1("k8s_ns1");
	c_info.m_labels[std::string("io.kubernetes.pod.namespace")] = ns1;
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 2);
	ASSERT_EQ(m_container_start_count->get_container_counts_for_k8s_namespace(ns1), 1);

	// Add it again and see if count goes up
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 3);
	ASSERT_EQ(m_container_start_count->get_container_counts_for_k8s_namespace(ns1), 2);

	// add another namespace
	std::string ns2("k8s_ns2");
	c_info.m_labels[std::string("io.kubernetes.pod.namespace")] = ns2;
	add_container(c_info);
	ASSERT_EQ(m_container_start_count->get_host_container_counts() , 4);
	ASSERT_EQ(m_container_start_count->get_container_counts_for_k8s_namespace(ns2), 1);
}
