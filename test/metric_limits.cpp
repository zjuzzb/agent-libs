#include <gtest.h>
#include "metric_limits.h"
#include "stopwatch.h"

TEST(metric_limits, filter)
{
	std::string filter;
	metrics_filter_vec filters({{"haproxy.backend*", true}, {"test.*", true}, {"test2.*.?othin?", true},
							   {"haproxy.*", false}, {"redis.*", false}, {"test.*", false}, {"test2.*.somethin?", false}});
	metric_limits ml(filters);
	std::string metric("haproxy.frontend.bytes");
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(1u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.backend*");
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(2u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.backend*");

	metric = "redis.keys";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "redis.*");
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(3u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "redis.*");

	metric = "mysql.queries.count";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(4u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());

	metric = "test.something";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "test.*");
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(5u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "test.*");

	metric = "test2.dummy.something";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "test2.*.somethin?");
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(6u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "test2.*.somethin?");

	metric = "test2.dummy.something2";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(7u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());

	metric = "test2.dummy.nothing";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "test2.*.?othin?");
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(8u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "test2.*.?othin?");

	metric = "test2.dummy.nothing2";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_TRUE(ml.has(metric));
	ASSERT_EQ(9u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());

	metrics_filter_vec filter2({{"haproxy.*", true}, {"haproxy.*", false}});
	metric_limits ml2(filter2);
	metric = "haproxy.frontend.bytes";
	EXPECT_FALSE(ml2.has(metric));
	EXPECT_TRUE(ml2.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml2.has(metric));
	ASSERT_EQ(1u, ml2.cached());
	EXPECT_TRUE(ml2.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml2.has(metric));
	EXPECT_TRUE(ml2.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml2.has(metric));
	ASSERT_EQ(2u, ml2.cached());
	EXPECT_TRUE(ml2.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");

	metric = "something.backend.request";
	EXPECT_FALSE(ml2.has(metric));
	EXPECT_TRUE(ml2.allow(metric, filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_TRUE(ml2.has(metric));
	ASSERT_EQ(3u, ml2.cached());
	EXPECT_TRUE(ml2.allow(metric, filter));
	EXPECT_TRUE(filter.empty());

	metrics_filter_vec filter3({{"haproxy.*", true}, {"*", false}});
	metric_limits ml3(filter3);
	metric = "haproxy.frontend.bytes";
	EXPECT_FALSE(ml3.has(metric));
	EXPECT_TRUE(ml3.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml3.has(metric));
	ASSERT_EQ(1u, ml3.cached());
	EXPECT_TRUE(ml3.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml3.has(metric));
	EXPECT_TRUE(ml3.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml3.has(metric));
	ASSERT_EQ(2u, ml3.cached());
	EXPECT_TRUE(ml3.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");

	metric = "something.backend.request";
	EXPECT_FALSE(ml3.has(metric));
	EXPECT_FALSE(ml3.allow(metric, filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_TRUE(ml3.has(metric));
	ASSERT_EQ(3u, ml3.cached());
	EXPECT_FALSE(ml3.allow(metric, filter));
	EXPECT_TRUE(filter == "*");
}

TEST(metric_limits, cache)
{
	std::string filter;
	metrics_filter_vec filters({{"haproxy.backend*", true}, {"test.*", true}, {"test2.*.?othin?", true},
							   {"haproxy.*", false}, {"redis.*", false}, {"test.*", false}, {"test2.*.somethin?", false}});

	metric_limits ml(filters, 3u, 2u);
	ASSERT_EQ(3u, ml.cache_max_entries());
	ASSERT_EQ(2u, ml.cache_expire_seconds());

	std::string metric("haproxy.frontend.bytes");
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml.has(metric));
	EXPECT_EQ(1u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");

	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.backend*");
	EXPECT_TRUE(ml.has(metric));
	EXPECT_EQ(2u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.backend*");

	metric = "redis.keys";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "redis.*");
	EXPECT_TRUE(ml.has(metric));
	EXPECT_EQ(3u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "redis.*");

	metric = "mysql.queries.count";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_FALSE(ml.has(metric));
	EXPECT_EQ(3u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());

	// check cache is purged
	std::cout << "Wait " << ml.cache_expire_seconds() + 1 << "s for cache to expire ..." << std::endl;
	sleep(ml.cache_expire_seconds() + 1);
	EXPECT_EQ(0u, ml.cached());

	metric = "haproxy.frontend.bytes";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml.has(metric));
	EXPECT_EQ(1u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.*");
	
	metric = "haproxy.backend.request";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.backend*");
	EXPECT_TRUE(ml.has(metric));
	EXPECT_EQ(2u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "haproxy.backend*");

	metric = "redis.keys";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "redis.*");
	EXPECT_TRUE(ml.has(metric));
	EXPECT_EQ(3u, ml.cached());
	EXPECT_FALSE(ml.allow(metric, filter));
	EXPECT_TRUE(filter == "redis.*");

	metric = "mysql.queries.count";
	EXPECT_FALSE(ml.has(metric));
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_FALSE(ml.has(metric));
	EXPECT_EQ(3u, ml.cached());
	EXPECT_TRUE(ml.allow(metric, filter));
	EXPECT_TRUE(filter.empty());

	ml.clear_cache();
	ASSERT_EQ(0u, ml.cached());

	metric_limits ml2(filters, 3000u, 2u);
	sinsp_stopwatch sw;
	std::chrono::microseconds::rep sum = 0;
	for(unsigned i = 0; i < ml2.cache_max_entries(); ++i)
	{
		std::string s(std::to_string(i) + metric);
		sw.start();
		bool b = ml2.allow(s, filter);
		sw.stop();
		sum += sw.elapsed<std::chrono::microseconds>();
		EXPECT_TRUE(b);
		EXPECT_TRUE(filter.empty());
		EXPECT_TRUE(ml2.has(s));
		EXPECT_EQ(i + 1, ml2.cached());
	}
	uint64_t c = ml2.cached();
	EXPECT_EQ(c, ml2.cache_max_entries());
	std::cout << c << " items, full cache populated in " <<
		sum << " us" << std::endl;
	EXPECT_FALSE(ml2.has("xyz"));
	sw.start();
	bool a = ml2.allow("xyz", filter);
	sw.stop();
	EXPECT_TRUE(a);
	EXPECT_TRUE(filter.empty());
	EXPECT_FALSE(ml2.has("xyz"));
	std::cout << c << " items, non-cached item lookup in " <<
		sw.elapsed<std::chrono::nanoseconds>() << " ns" << std::endl;
	std::string s(std::to_string(ml2.cache_max_entries() - 5) + metric);
	EXPECT_TRUE(ml2.has(s));
	sw.start();
	a = ml2.allow(s, filter);
	sw.stop();
	EXPECT_TRUE(a);
	EXPECT_TRUE(filter.empty());
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
	EXPECT_TRUE(ml2.allow("xyz", filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_TRUE(ml2.has("xyz"));
}

TEST(metric_limits, empty)
{
	metrics_filter_vec filters({{"", true}});

	try
	{
		metric_limits ml(filters);
	}
	catch(std::exception&)
	{
		return;
	}

	EXPECT_TRUE(false);
}

TEST(metric_limits, star1)
{
	metrics_filter_vec filters({{"*", true}});

	try
	{
		metric_limits ml(filters);
	}
	catch(std::exception&)
	{
		return;
	}

	EXPECT_TRUE(false);
}

TEST(metric_limits, star2)
{
	metrics_filter_vec filters({{"*", true}, {"blah", true}});

	try
	{
		metric_limits ml(filters);
	}
	catch(std::exception&)
	{
		return;
	}

	EXPECT_TRUE(false);
}

TEST(metric_limits, filter_vec)
{
	metrics_filter_vec filters({{"*", false}, {"blah", true}});
	EXPECT_EQ(2u, filters.size());
	metric_limits::optimize_exclude_all(filters);
	EXPECT_EQ(1u, filters.size());
	EXPECT_EQ(filters[0].filter(), "*");
	EXPECT_FALSE(filters[0].included());

	filters = {{"*", true}, {"blah", true}};
	EXPECT_TRUE(metric_limits::first_includes_all(filters));
	EXPECT_EQ(filters[0].filter(), "*");
	EXPECT_TRUE(filters[0].included());

	const unsigned CUSTOM_METRICS_FILTERS_HARD_LIMIT = 10;
	filters.clear();
	for(unsigned i = 0; i <= CUSTOM_METRICS_FILTERS_HARD_LIMIT; ++i)
	{
		filters.push_back({std::to_string(i) + "xyz", i % 2});
	}
	ASSERT_EQ(CUSTOM_METRICS_FILTERS_HARD_LIMIT + 1, filters.size());
	if(filters.size() > CUSTOM_METRICS_FILTERS_HARD_LIMIT)
	{
		filters.erase(filters.begin() + CUSTOM_METRICS_FILTERS_HARD_LIMIT, filters.end());
	}
	EXPECT_EQ(CUSTOM_METRICS_FILTERS_HARD_LIMIT, filters.size());
}

TEST(metric_limits, projspec)
{
	std::string filter;
	metrics_filter_vec filters({{"test.*", true}, {"test.*", false}, {"haproxy.backend.*", true}, {"haproxy.*", false}, {"redis.*", false}});
	metric_limits ml(filters);
	EXPECT_FALSE(ml.has("haproxy.frontend.bytes"));
	EXPECT_FALSE(ml.allow("haproxy.frontend.bytes", filter));
	EXPECT_TRUE(filter == "haproxy.*");
	EXPECT_TRUE(ml.has("haproxy.frontend.bytes"));

	EXPECT_FALSE(ml.has("haproxy.backend.request"));
	EXPECT_TRUE(ml.allow("haproxy.backend.request", filter));
	EXPECT_TRUE(filter == "haproxy.backend.*");
	EXPECT_TRUE(ml.has("haproxy.backend.request"));

	EXPECT_FALSE(ml.has("redis.keys"));
	EXPECT_FALSE(ml.allow("redis.keys", filter));
	EXPECT_TRUE(filter == "redis.*");
	EXPECT_TRUE(ml.has("redis.keys"));

	EXPECT_FALSE(ml.has("mysql.queries.count"));
	EXPECT_TRUE(ml.allow("mysql.queries.count", filter));
	EXPECT_TRUE(filter.empty());
	EXPECT_TRUE(ml.has("mysql.queries.count"));

	EXPECT_FALSE(ml.has("test.\\*"));
	EXPECT_TRUE(ml.allow("test.\\*", filter));
	EXPECT_TRUE(filter == "test.*");
	EXPECT_TRUE(ml.has("test.\\*"));
}

TEST(metric_limits, statsd)
{
	std::string filter;
	metrics_filter_vec f({{"*1?", true}, {"*", false}});
	metric_limits ml(f);

	EXPECT_TRUE(ml.allow("totam.sunt.consequatur.numquam.aperiam10", filter));
	EXPECT_TRUE(filter == "*1?");
	EXPECT_TRUE(ml.allow("totam.sunt.consequatur.numquam.aperiam10", filter));
	EXPECT_TRUE(filter == "*1?");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam5", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam8", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam8", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam4", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam9", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam5", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam4", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam3", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam7", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam7", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam6", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam1", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam9", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam6", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam2", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam1", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam3", filter));
	EXPECT_TRUE(filter == "*");
	EXPECT_FALSE(ml.allow("totam.sunt.consequatur.numquam.aperiam2", filter));
	EXPECT_TRUE(filter == "*");

	EXPECT_EQ(10u, ml.cached());
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam10"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam5"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam8"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam4"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam9"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam3"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam7"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam6"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam1"));
	EXPECT_TRUE(ml.has("totam.sunt.consequatur.numquam.aperiam2"));
}
