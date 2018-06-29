#include <gtest.h>
#include "k8s_limits.h"

#define DEFAULT_CACHE_SIZE 10000

TEST(k8s_limits, purge_proto_structure)
{
	std::string filter;
	filter_vec_t filters({{"*.kubernetes.io/*", false},
			{"*.pod-template-hash", false},
			{"*.pod-template-generation", false},
			{"*", true}});

	k8s_limits kl(filters);

	draiosproto::container_group cg;

	cg.mutable_tags()->insert({"abc.kubernetes.io/def", "a_value"});
	cg.mutable_tags()->insert({"kubernetes.pod.label.pod-template-hash", "3316313349"});
	cg.mutable_tags()->insert({"ground_control", "to_major_tom"});

	ASSERT_EQ(cg.tags().size(), 3u);

	kl.purge_tags(cg);

	EXPECT_EQ(cg.tags().size(), 1u);
	EXPECT_EQ(std::begin(cg.tags())->first, "ground_control");
}
