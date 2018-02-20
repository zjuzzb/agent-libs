#include <gtest.h>
#include <label_limits.h>

TEST(label_limits, empty_filter)
{
	filter_vec_t filters({});

	label_limits ll(filters);

	std::string filter;
	EXPECT_TRUE(ll.allow("any_label", filter));
}

TEST(label_limits, default_excluded_labels)
{
	filter_vec_t filters({{"com.docker.ucp.*", false},
			{"*", true}});

	label_limits ll(filters);
	std::string filter;

	EXPECT_FALSE(ll.allow("com.docker.ucp.InstanceID", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.access.label", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.collection", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.collection.root", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.collection.swarm", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.min_cs_engine_version", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.min_ee_engine_version", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.min_oss_engine_version", filter));
	EXPECT_FALSE(ll.allow("com.docker.ucp.upgrades_from", filter));
	EXPECT_TRUE(ll.allow("any_other", filter));
}
