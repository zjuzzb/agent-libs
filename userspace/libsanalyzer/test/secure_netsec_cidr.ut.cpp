#include "scoped_configuration.h"
#include "secure_audit_data_ready_handler.h"
#include "unique_ptr_resetter.h"
#include "feature_manager.h"

#include <analyzer.h>
#include <connectinfo.h>
#include <gtest.h>
#include <memory>
#include <scoped_config.h>
#include <secure_netsec.h>
#include <sinsp_mock.h>

using namespace test_helpers;

class secure_netsec_cidr_test : public ::testing::Test
{
protected:
	virtual void SetUp()
	{
		test_helpers::scoped_config<bool> enable_security("security.enabled", true);
		test_helpers::scoped_config<bool> enable_network_topology("network_topology.enabled", true);
	}

	virtual void TearDown() {}
};

TEST(secure_netsec_cidr_test, valid_config)
{
	test_helpers::scoped_config<std::string> enable_network_topology_cluster_cidr("network_topology.cluster_cidr", "98.0.0.0/10");
	test_helpers::scoped_config<std::string> enable_network_topology_service_cidr("network_topology.service_cidr", "99.0.0.0/12");

	feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL);
	secure_netsec netsec;

	netsec.init(nullptr, nullptr);
	ASSERT_EQ(netsec.is_k8s_cidr_configured(), true);
}

TEST(secure_netsec_cidr_test, cidr_config_invalid) // and valid service cidr
{
	test_helpers::scoped_config<std::string> enable_network_topology_cluster_cidr("network_topology.cluster_cidr", "1.1.1.1-32");
	test_helpers::scoped_config<std::string> enable_network_topology_service_cidr("network_topology.service_cidr", "100.0.0.0/10");

	feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL);
	secure_netsec netsec;

	netsec.init(nullptr, nullptr);
	ASSERT_EQ(netsec.is_k8s_cidr_configured(), false);
}

TEST(secure_netsec_cidr_test, cidr_validation)
{
	uint32_t netip, netmask;
	bool is_valid_k8s_cidr;

	// empty cidr string
	is_valid_k8s_cidr = parse_k8s_cidr("", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, false);

	// bogus string
	is_valid_k8s_cidr = parse_k8s_cidr("iamnotavalidcidr", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, false);

	// invalid ip address
	is_valid_k8s_cidr = parse_k8s_cidr("1.1.x.1/24", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, false);

	// invalid network mask address
	is_valid_k8s_cidr = parse_k8s_cidr("1.1.1.1/xx", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, false);

	// valid ip and netmask
	is_valid_k8s_cidr = parse_k8s_cidr("100.0.0.0/1", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, true);

	is_valid_k8s_cidr = parse_k8s_cidr("100.0.0.0/12", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, true);

	is_valid_k8s_cidr = parse_k8s_cidr("100.96.0.0/11", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, true);
	ASSERT_EQ(netip, 0x64600000);
	ASSERT_EQ(netmask, 0xffe00000);

	is_valid_k8s_cidr = parse_k8s_cidr("100.96.0.0/32", &netip, &netmask);
	ASSERT_EQ(is_valid_k8s_cidr, true);
	ASSERT_EQ(netip, 0x64600000);
	ASSERT_EQ(netmask, 0xffffffff);
}
