/**
 * @file
 *
 * Unit tests for dummy_statsd_stats_source.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dummy_statsd_stats_source.h"
#include <string>
#include <vector>
#include <gtest.h>

using test_helpers::dummy_statsd_stats_source;

namespace
{

using taglist = dummy_statsd_stats_source::taglist;

void test_one_count_metric(const std::string& id = "",
                           const taglist& tags = taglist())
{
	const std::string name = "my_metric_name";
	const double value = 1.0;
	const uint64_t ts = 1560367758;
	dummy_statsd_stats_source source;

	ASSERT_NO_THROW(
		source.add_counter(name, value, ts, id, tags);
	);

	const statsd_stats_source::container_statsd_map metric_map =
		source.read_metrics();

	auto itr = metric_map.find(id);

	ASSERT_NE(itr, metric_map.end());
	ASSERT_EQ(1, std::get<1>(itr->second));
	ASSERT_EQ(1, std::get<0>(itr->second).size());
	ASSERT_EQ(name, std::get<0>(itr->second)[0].name());
	ASSERT_EQ(statsd_metric::type_t::COUNT, std::get<0>(itr->second)[0].type());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].value());

	if(!tags.empty())
	{
		for(const auto& t : tags)
		{
			const auto colon_index = t.find(":");
			const std::string tag_name = t.substr(0, colon_index);
			const std::string tag_value = t.substr(colon_index + 1);

			const std::map<std::string, std::string>& m =
				std::get<0>(itr->second)[0].tags();

			const auto elem = m.find(tag_name);

			ASSERT_NE(elem, m.end());
			ASSERT_EQ(tag_value, elem->second); 
		}
	}
}

void test_two_count_metrics(const std::string& id = "")
{
	const std::string name1 = "my_metric_name1";
	const std::string name2 = "my_metric_name2";
	const double value1 = 1.0;
	const double value2 = 2.0;
	const uint64_t ts1 = 1560367758;
	const uint64_t ts2 = 1560367759;
	dummy_statsd_stats_source source;

	ASSERT_NO_THROW(
		source.add_counter(name1, value1, ts1, id);
		source.add_counter(name2, value2, ts2, id);
	);

	const statsd_stats_source::container_statsd_map metric_map =
		source.read_metrics();

	auto itr = metric_map.find(id);

	ASSERT_NE(itr, metric_map.end());
	ASSERT_EQ(2, std::get<1>(itr->second)); // Should be the last ts
	ASSERT_EQ(2, std::get<0>(itr->second).size());

	ASSERT_EQ(name1, std::get<0>(itr->second)[0].name());
	ASSERT_EQ(statsd_metric::type_t::COUNT, std::get<0>(itr->second)[0].type());
	ASSERT_DOUBLE_EQ(value1, std::get<0>(itr->second)[0].value());

	ASSERT_EQ(name2, std::get<0>(itr->second)[1].name());
	ASSERT_EQ(statsd_metric::type_t::COUNT, std::get<0>(itr->second)[1].type());
	ASSERT_DOUBLE_EQ(value2, std::get<0>(itr->second)[1].value());
}

void test_one_gauge_metric(const std::string& id = "")
{
	const std::string name = "my_metric_name";
	const double value = 1.0;
	const uint64_t ts = 1560367758;
	dummy_statsd_stats_source source;

	ASSERT_NO_THROW(
		source.add_gauge(name, value, ts, id);
	);

	const statsd_stats_source::container_statsd_map metric_map =
		source.read_metrics();

	auto itr = metric_map.find(id);

	ASSERT_NE(itr, metric_map.end());
	ASSERT_EQ(1, std::get<1>(itr->second));
	ASSERT_EQ(1, std::get<0>(itr->second).size());
	ASSERT_EQ(name, std::get<0>(itr->second)[0].name());
	ASSERT_EQ(statsd_metric::type_t::GAUGE, std::get<0>(itr->second)[0].type());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].value());
}

void test_one_set_metric(const std::string& id = "")
{
	const std::string name = "my_metric_name";
	const double value = 1.0;
	const uint64_t ts = 1560367758;
	dummy_statsd_stats_source source;

	ASSERT_NO_THROW(
		source.add_set(name, value, ts, id);
	);

	const statsd_stats_source::container_statsd_map metric_map =
		source.read_metrics();

	auto itr = metric_map.find(id);

	ASSERT_NE(itr, metric_map.end());
	ASSERT_EQ(1, std::get<1>(itr->second));
	ASSERT_EQ(1, std::get<0>(itr->second).size());
	ASSERT_EQ(name, std::get<0>(itr->second)[0].name());
	ASSERT_EQ(statsd_metric::type_t::SET, std::get<0>(itr->second)[0].type());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].value());
}

void test_one_histogram_metric(const std::string& id = "")
{
	const std::string name = "my_metric_name";
	const double value = 42.0;
	const uint64_t ts = 1560367762;
	dummy_statsd_stats_source source;

	ASSERT_NO_THROW(
		source.add_histogram(name, value, ts, id);
	);

	const statsd_stats_source::container_statsd_map metric_map =
		source.read_metrics();

	auto itr = metric_map.find(id);

	ASSERT_NE(itr, metric_map.end());
	ASSERT_EQ(1, std::get<1>(itr->second));
	ASSERT_EQ(1, std::get<0>(itr->second).size());
	ASSERT_EQ(name, std::get<0>(itr->second)[0].name());
	ASSERT_EQ(statsd_metric::type_t::HISTOGRAM, std::get<0>(itr->second)[0].type());
	// Value seems not defined for histogram stats
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].sum());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].mean());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].min());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].max());
	ASSERT_EQ(1, std::get<0>(itr->second)[0].count());
	ASSERT_DOUBLE_EQ(0.0, std::get<0>(itr->second)[0].stdev());
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].percentile(50));
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].percentile(95));
	ASSERT_DOUBLE_EQ(value, std::get<0>(itr->second)[0].percentile(99));
}

} // end namespace

/**
 * Ensure that add_counter() with one host count metric adds the expected
 * metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_host_count_metric)
{
	test_one_count_metric();
}

/**
 * Ensure that add_counter() with one container count metric adds the expected
 * metric.
 */
TEST(dummy_statsd_stats_source_test, one_container_count_metric)
{
	test_one_count_metric("aaabbbcccddd");
}

/**
 * Ensure that add_counter() with one host count metric adds the expected
 * metric, including the associated tags.
 */
TEST(dummy_statsd_stats_source_test, one_host_count_metric_with_tags)
{
	test_one_count_metric("", {"a:b", "b:c"});
}

/**
 * Ensure that add_counter() with one container count metric adds the expected
 * metric, including the associated tags.
 */
TEST(dummy_statsd_stats_source_test, one_container_count_metric_with_tags)
{
	test_one_count_metric("aaabbbcccddd", {"a:b", "b:c"});
}

/**
 * Ensure that two calls to add_counter() add the expected host metrics.
 */
TEST(dummy_statsd_stats_source_test, two_host_count_metrics)
{
	test_two_count_metrics();
}

/**
 * Ensure that two calls to add_counter() add the expected container metrics.
 */
TEST(dummy_statsd_stats_source_test, two_container_count_metrics)
{
	test_two_count_metrics("aaabbbcccddd");
}

/**
 * Ensure that add_set() with one host set metric adds the expected
 * metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_host_set_metric)
{
	test_one_set_metric();
}

/**
 * Ensure that add_set() with one container set metric adds the expected
 * metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_container_set_metric)
{
	test_one_set_metric("aaabbbcccddd");
}

/**
 * Ensure that add_gauge() with one host gauge metric adds the expected
 * metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_host_gauge_metric)
{
	test_one_gauge_metric();
}

/**
 * Ensure that add_gauge() with one container gauge metric adds the expected
 * metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_container_gauge_metric)
{
	test_one_gauge_metric("aaabbbcccddd");
}

/**
 * Ensure that add_histogram() with one host histogram metric adds the expected
 * metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_host_histogram_metric)
{
	test_one_histogram_metric();
}

/**
 * Ensure that add_histogram() with one container histogram metric adds the
 * expected metric (includes no tags).
 */
TEST(dummy_statsd_stats_source_test, one_container_histogram_metric)
{
	test_one_histogram_metric("aaabbbcccddd");
}
