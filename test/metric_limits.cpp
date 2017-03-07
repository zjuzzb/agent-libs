#include <gtest.h>
#include "metric_limits.h"

TEST(metric_limits, filter)
{
	metric_limits::list_t excluded({"haproxy.*", "redis.*", "test.*", "test2.*.somethin?"});
	metric_limits::list_t included({"haproxy.backend*", "test.*", "test2.*.?othin?"});

	metric_limits ml(excluded, included);
	std::string metric("haproxy.frontend.bytes");
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(1u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(2u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "redis.keys";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(3u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));

	metric = "mysql.queries.count";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(4u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "test.something";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(5u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "test2.dummy.something";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(6u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));

	metric = "test2.dummy.something2";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(7u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "test2.dummy.nothing";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(8u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "test2.dummy.nothing2";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(9u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric_limits::list_t excluded2({"haproxy.*"});
	metric_limits::list_t included2({"haproxy.*"});
	metric_limits ml2(excluded2, included2);
	metric = "haproxy.frontend.bytes";
	EXPECT_FALSE(ml2.has(metric));
	EXPECT_TRUE(ml2.allow(metric));
	EXPECT_TRUE(ml2.has(metric));
	ASSERT_EQ(1u, ml2.cached());
	EXPECT_TRUE(ml2.allow(metric));

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml2.has(metric));
	EXPECT_TRUE(ml2.allow(metric));
	EXPECT_TRUE(ml2.has(metric));
	ASSERT_EQ(2u, ml2.cached());
	EXPECT_TRUE(ml2.allow(metric));

	metric = "something.backend.request";
	EXPECT_FALSE(ml2.has(metric));
	EXPECT_TRUE(ml2.allow(metric));
	EXPECT_TRUE(ml2.has(metric));
	ASSERT_EQ(3u, ml2.cached());
	EXPECT_TRUE(ml2.allow(metric));

	metric_limits::list_t excluded3({"*"});
	metric_limits::list_t included3({"haproxy.*"});
	metric_limits ml3(excluded3, included3);
	metric = "haproxy.frontend.bytes";
	EXPECT_FALSE(ml3.has(metric));
	EXPECT_TRUE(ml3.allow(metric));
	EXPECT_TRUE(ml3.has(metric));
	ASSERT_EQ(1u, ml3.cached());
	EXPECT_TRUE(ml3.allow(metric));

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml3.has(metric));
	EXPECT_TRUE(ml3.allow(metric));
	EXPECT_TRUE(ml3.has(metric));
	ASSERT_EQ(2u, ml3.cached());
	EXPECT_TRUE(ml3.allow(metric));

	metric = "something.backend.request";
	EXPECT_FALSE(ml3.has(metric));
	EXPECT_FALSE(ml3.allow(metric));
	EXPECT_TRUE(ml3.has(metric));
	ASSERT_EQ(3u, ml3.cached());
	EXPECT_FALSE(ml3.allow(metric));
}

TEST(metric_limits, cache)
{
	metric_limits::list_t excluded({"haproxy.*", "redis.*", "test.*", "test2.*.somethin?"});
	metric_limits::list_t included({"haproxy.backend*", "test.*", "test2.*.?othin?"});

	metric_limits ml(excluded, included, 3u, 2u);
	std::string metric("haproxy.frontend.bytes");
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(1u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));
	
	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(2u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "redis.keys";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(3u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));

	metric = "mysql.queries.count";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_FALSE(ml.has(metric));
	ASSERT_EQ(3u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	sleep(3);
	ASSERT_EQ(0u, ml.cached());

	metric = "haproxy.frontend.bytes";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(1u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));
	
	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(2u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));

	metric = "redis.keys";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric));
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(3u, ml.cached());
	EXPECT_FALSE(ml.allow(metric));

	metric = "mysql.queries.count";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric));
	EXPECT_FALSE(ml.has(metric));
	ASSERT_EQ(3u, ml.cached());
	EXPECT_TRUE(ml.allow(metric));
}
