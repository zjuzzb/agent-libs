#include <gtest.h>
#include "metric_limits.h"
#include "stopwatch.h"

TEST(metric_limits, filter)
{
	metrics_filter_vec filter({{"haproxy.backend*", true}, {"test.*", true}, {"test2.*.?othin?", true},
							   {"haproxy.*", false}, {"redis.*", false}, {"test.*", false}, {"test2.*.somethin?", false}});
	metric_limits ml(filter);
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

	metrics_filter_vec filter2({{"haproxy.*", true}, {"haproxy.*", false}});
	metric_limits ml2(filter2);
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

	metrics_filter_vec filter3({{"haproxy.*", true}, {"*", false}});
	metric_limits ml3(filter3);
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
	metrics_filter_vec filter({{"haproxy.backend*", true}, {"test.*", true}, {"test2.*.?othin?", true},
							   {"haproxy.*", false}, {"redis.*", false}, {"test.*", false}, {"test2.*.somethin?", false}});

	metric_limits ml(filter, 3u, 2u);
	ASSERT_EQ(3u, ml.cache_max_entries());
	ASSERT_EQ(2u, ml.cache_expire_seconds());

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

	ml.clear_cache();
	ASSERT_EQ(0u, ml.cached());

	metric_limits ml2(filter, 3000u, 2u);
	sinsp_stopwatch sw;
	std::chrono::microseconds::rep sum = 0;
	for(unsigned i = 0; i < ml2.cache_max_entries(); ++i)
	{
		std::string s(std::to_string(i) + metric);
		sw.start();
		bool b = ml2.allow(s);
		sw.stop();
		sum += sw.elapsed<std::chrono::microseconds>();
		EXPECT_TRUE(b);
		EXPECT_TRUE(ml2.has(s));
		EXPECT_EQ(i + 1, ml2.cached());
	}
	uint64_t c = ml2.cached();
	EXPECT_EQ(c, ml2.cache_max_entries());
	std::cout << c << " items, full cache populated in " <<
		sum << " us" << std::endl;
	EXPECT_FALSE(ml2.has("xyz"));
	sw.start();
	bool a = ml2.allow("xyz");
	sw.stop();
	EXPECT_TRUE(a);
	EXPECT_FALSE(ml2.has("xyz"));
	std::cout << c << " items, non-cached item lookup in " <<
		sw.elapsed<std::chrono::nanoseconds>() << " ns" << std::endl;
	std::string s(std::to_string(ml2.cache_max_entries() - 5) + metric);
	EXPECT_TRUE(ml2.has(s));
	sw.start();
	a = ml2.allow(s);
	sw.stop();
	EXPECT_TRUE(a);
	EXPECT_TRUE(ml2.has(s));
	std::cout << c << " items, cached item lookup in " <<
		sw.elapsed<std::chrono::nanoseconds>() << " ns" << std::endl;
	sleep(3);
	sw.start();
	ml2.purge_cache();
	sw.stop();
	std::cout << c << " items, full cache emptied in " <<
		sw.elapsed<std::chrono::microseconds>() << " us" << std::endl;
	EXPECT_EQ(0u, ml2.cached());
	EXPECT_FALSE(ml2.has("xyz"));
	EXPECT_TRUE(ml2.allow("xyz"));
	EXPECT_TRUE(ml2.has("xyz"));
}

TEST(metric_limits, empty)
{
	metrics_filter_vec filter({{"", true}});

	try
	{
		metric_limits ml(filter);
	}
	catch(std::exception&)
	{
		return;
	}

	EXPECT_TRUE(false);
}

TEST(metric_limits, star1)
{
	metrics_filter_vec filter({{"*", true}});

	try
	{
		metric_limits ml(filter);
	}
	catch(std::exception&)
	{
		return;
	}

	EXPECT_TRUE(false);
}

TEST(metric_limits, star2)
{
	metrics_filter_vec filter({{"*", true}, {"blah", true}});

	try
	{
		metric_limits ml(filter);
	}
	catch(std::exception&)
	{
		return;
	}

	EXPECT_TRUE(false);
}

TEST(metric_limits, projspec)
{
	metrics_filter_vec filters({{"test.*", true}, {"test.*", false}, {"haproxy.backend.*", true}, {"haproxy.*", false}, {"redis.*", false}});
	metric_limits ml(filters);
	EXPECT_FALSE(ml.has("haproxy.frontend.bytes"));
	EXPECT_FALSE(ml.allow("haproxy.frontend.bytes"));
	EXPECT_TRUE(ml.has("haproxy.frontend.bytes"));

	EXPECT_FALSE(ml.has("haproxy.backend.request"));
	EXPECT_TRUE(ml.allow("haproxy.backend.request"));
	EXPECT_TRUE(ml.has("haproxy.backend.request"));

	EXPECT_FALSE(ml.has("redis.keys"));
	EXPECT_FALSE(ml.allow("redis.keys"));
	EXPECT_TRUE(ml.has("redis.keys"));

	EXPECT_FALSE(ml.has("mysql.queries.count"));
	EXPECT_TRUE(ml.allow("mysql.queries.count"));
	EXPECT_TRUE(ml.has("mysql.queries.count"));

	EXPECT_FALSE(ml.has("test.\\*"));
	EXPECT_TRUE(ml.allow("test.\\*"));
	EXPECT_TRUE(ml.has("test.\\*"));
}
