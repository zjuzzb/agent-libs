/**
 * @file
 *
 * Unit tests for statsd_metric.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsd_metric.h"
#include <gtest.h>

//-----------------------------------------------------------------------------
//-- Constructor
//-----------------------------------------------------------------------------

/**
 * Ensure that a newly-constructed statsd metric has the expected timestamp.
 */
TEST(statsd_metric_test, initial_timestamp_is_zero)
{
	statsd_metric metric;

	ASSERT_EQ(0, metric.timestamp());
}

/**
 * Ensure that a newly-constructed statsd metric has an empty name.
 */
TEST(statsd_metric_test, initial_name_is_empty_string)
{
	statsd_metric metric;

	ASSERT_EQ("", metric.name());
}

/**
 * Ensure that a newly-constructed statsd metric has an empty container_id.
 */
TEST(statsd_metric_test, initial_container_id_is_empty_string)
{
	statsd_metric metric;

	ASSERT_EQ("", metric.container_id());
}

/**
 * Ensure that a newly-constructed statsd metric's type is NONE.
 */
TEST(statsd_metric_test, initial_type_is_NONE)
{
	statsd_metric metric;

	ASSERT_EQ(statsd_metric::type_t::NONE, metric.type());
}

/**
 * Ensure that a newly-constructed statsd metric's value is 0.0.
 */
TEST(statsd_metric_test, initial_value_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.value());
}

/**
 * Ensure that a newly-constructed statsd metric's sum is 0.0.
 */
TEST(statsd_metric_test, initial_sum_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.sum());
}

/**
 * Ensure that a newly-constructed statsd metric's mean is 0.0.
 */
TEST(statsd_metric_test, initial_mean_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.mean());
}

/**
 * Ensure that a newly-constructed statsd metric's min is 0.0.
 */
TEST(statsd_metric_test, initial_min_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.min());
}

/**
 * Ensure that a newly-constructed statsd metric's max is 0.0.
 */
TEST(statsd_metric_test, initial_max_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.max());
}

/**
 * Ensure that a newly-constructed statsd metric's count is 0.0.
 */
TEST(statsd_metric_test, initial_count_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.count());
}

/**
 * Ensure that a newly-constructed statsd metric's stdev is 0.0.
 */
TEST(statsd_metric_test, initial_stdev_is_zero)
{
	statsd_metric metric;

	ASSERT_DOUBLE_EQ(0.0, metric.stdev());
}

/**
 * Ensure that a newly-constructed statsd metric has no tags.
 */
TEST(statsd_metric_test, initial_tags_empty)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.tags().empty());
}

//-----------------------------------------------------------------------------
//-- parse_line() - host counter metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a host counter metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_host_count_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name|42.000000|1563315016"));
	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a host counter metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_host_count_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name|42.000000|1563315016"));
	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a host counter metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_host_count_container_id_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name|42.000000|1563315016"));
	ASSERT_EQ("", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a host counter metric's
 * value.
 */
TEST(statsd_metric_test, parse_line_host_count_value)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name|42.000000|1563315016"));
	ASSERT_DOUBLE_EQ(42.0, metric.value());
}

/**
 * Ensure that parse_line() can correctly parse a host counter metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_host_count_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name|42.000000|1563315016"));
	ASSERT_EQ(statsd_metric::type_t::COUNT, metric.type());
}

/**
 * Ensure that if no tags are included in a counter metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_host_count_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name|42.000000|1563315016"));
	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a counter metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_host_count_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name#tag_name=tag_value|42.000000|1563315016"));
	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a counter metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_host_count_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a counter metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_host_count_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.metric_name#tag_name1,tag_name2,tag_name3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

//-----------------------------------------------------------------------------
//-- parse_line() - host gauge metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a host gauge metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_host_gauge_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name|42.000000|1563315016"));
	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a host gauge metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_host_gauge_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name|42.000000|1563315016"));
	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a host gauge metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_host_gauge_container_id_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name|42.000000|1563315016"));
	ASSERT_EQ("", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a host gauge metric's
 * value.
 */
TEST(statsd_metric_test, parse_line_host_gauge_value)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name|42.000000|1563315016"));
	ASSERT_DOUBLE_EQ(42.0, metric.value());
}

/**
 * Ensure that parse_line() can correctly parse a host gauge metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_host_gauge_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name|42.000000|1563315016"));
	ASSERT_EQ(statsd_metric::type_t::GAUGE, metric.type());
}

/**
 * Ensure that if no tags are included in a gauge metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_host_gauge_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name|42.000000|1563315016"));
	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a gauge metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_host_gauge_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name#tag_name=tag_value|42.000000|1563315016"));
	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a gauge metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_host_gauge_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a gauge metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_host_gauge_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.metric_name#tag_name1,tag_name2,tag_name3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

//-----------------------------------------------------------------------------
//-- parse_line() - host set metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a host set metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_host_set_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name|42.000000|1563315016"));
	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a host set metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_host_set_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name|42.000000|1563315016"));
	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a host set metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_host_set_container_id_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name|42.000000|1563315016"));
	ASSERT_EQ("", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a host set metric's
 * value.
 */
TEST(statsd_metric_test, parse_line_host_set_value)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name|42.000000|1563315016"));
	ASSERT_DOUBLE_EQ(42.0, metric.value());
}

/**
 * Ensure that parse_line() can correctly parse a host set metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_host_set_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name|42.000000|1563315016"));
	ASSERT_EQ(statsd_metric::type_t::SET, metric.type());
}

/**
 * Ensure that if no tags are included in a set metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_host_set_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name|42.000000|1563315016"));
	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a set metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_host_set_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name#tag_name=tag_value|42.000000|1563315016"));
	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a set metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_host_set_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("set.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a set metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_host_set_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.metric_name#tag_name1,tag_name2,tag_name3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

//-----------------------------------------------------------------------------
//-- parse_line() - host histogram metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_host_histogram_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_host_histogram_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a host histogram metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_host_histogram_container_id_is_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ("", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * sum.
 */
TEST(statsd_metric_test, parse_line_host_histogram_sum)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(1.0, metric.sum());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * mean.
 */
TEST(statsd_metric_test, parse_line_host_histogram_mean)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(3.0, metric.mean());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * min.
 */
TEST(statsd_metric_test, parse_line_host_histogram_min)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(4.0, metric.min());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * max.
 */
TEST(statsd_metric_test, parse_line_host_histogram_max)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(5.0, metric.max());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * count.
 */
TEST(statsd_metric_test, parse_line_host_histogram_count)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(6.0, metric.count());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * stdev.
 */
TEST(statsd_metric_test, parse_line_host_histogram_stdev)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(7.0, metric.stdev());
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * p50, and the percentile(index) can read it.
 */
TEST(statsd_metric_test, parse_line_host_histogram_p50_percentile_v1)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(9.0, metric.percentile(50));
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * p50, and the percentile(percentile, value) can read it.
 */
TEST(statsd_metric_test, parse_line_host_histogram_p50_percentile_v2)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	double value = 142.5;
	ASSERT_TRUE(metric.percentile(50, value));
	ASSERT_DOUBLE_EQ(9.0, value);
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * p95, and the percentile(index) can read it.
 */
TEST(statsd_metric_test, parse_line_host_histogram_p95_percentile_v1)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(10.0, metric.percentile(95));
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * p95, and the percentile(percentile, value) can read it.
 */
TEST(statsd_metric_test, parse_line_host_histogram_p95_percentile_v2)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	double value = 142.5;
	ASSERT_TRUE(metric.percentile(95, value));
	ASSERT_DOUBLE_EQ(10.0, value);
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * p99, and the percentile(index) can read it.
 */
TEST(statsd_metric_test, parse_line_host_histogram_p99_percentile_v1)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(11.0, metric.percentile(99));
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * p99, and the percentile(percentile, value) can read it.
 */
TEST(statsd_metric_test, parse_line_host_histogram_p99_percentile_v2)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	double value = 142.5;
	ASSERT_TRUE(metric.percentile(99, value));
	ASSERT_DOUBLE_EQ(11.0, value);
}

/**
 * Ensure that parse_line() can correctly parse a host histogram metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_host_histogram_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(statsd_metric::type_t::HISTOGRAM, metric.type());
}

/**
 * Ensure that if no tags are included in a histogram metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_host_histogram_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a histogram metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_host_histogram_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name=tag_value.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a histogram metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_host_histogram_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a histogram metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_host_histogram_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if the timestamp differs between two different histogram
 * metric lines, the call to parse_line with the timestamp that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_host_histogram_mixed_timestamps_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315017"));
}

/**
 * Ensure that if the type differs between two different histogram
 * metric lines, the call to parse_line with the type that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_host_histogram_mixed_types_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("sets.metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));
}

/**
 * Ensure that if the metric name differs between two different histogram
 * metric lines, the call to parse_line with the name that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_host_histogram_mixed_names_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name1#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.metric_name2#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));

}

/**
 * Ensure that if one histogram metric is for the host, and another line
 * is for a container, the call to parse_line for the container fails.
 */
TEST(statsd_metric_test, parse_line_host_histogram_mixed_container_ids_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.a$metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));

}

/**
 * Ensure that if the tags differs between two different histogram
 * metric lines, the call to parse_line with the tags that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_host_histogram_mixed_tags_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.metric_name#tag_name1,tag_name2.sum_sq|2.000000|1563315016"));

}

//-----------------------------------------------------------------------------
//-- parse_line() - container counter metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a container counter metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_container_count_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a container counter metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_container_count_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a container counter metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_container_count_container_id_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ("123456789abc", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a container counter metric's
 * value.
 */
TEST(statsd_metric_test, parse_line_container_count_value)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_DOUBLE_EQ(42.0, metric.value());
}

/**
 * Ensure that parse_line() can correctly parse a container counter metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_container_count_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ(statsd_metric::type_t::COUNT, metric.type());
}

/**
 * Ensure that if no tags are included in a counter metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_container_count_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a counter metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_container_count_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name#tag_name=tag_value|42.000000|1563315016"));
	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a counter metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_container_count_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a counter metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_container_count_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("counts.123456789abc$metric_name#tag_name1,tag_name2,tag_name3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

//-----------------------------------------------------------------------------
//-- parse_line() - container gauge metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a container gauge metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_container_gauge_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a container gauge metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_container_gauge_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a container gauge metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_container_gauge_container_id_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ("123456789abc", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a container gauge metric's
 * value.
 */
TEST(statsd_metric_test, parse_line_container_gauge_value)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_DOUBLE_EQ(42.0, metric.value());
}

/**
 * Ensure that parse_line() can correctly parse a container gauge metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_container_gauge_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ(statsd_metric::type_t::GAUGE, metric.type());
}

/**
 * Ensure that if no tags are included in a gauge metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_container_gauge_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a gauge metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_container_gauge_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name#tag_name=tag_value|42.000000|1563315016"));
	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a gauge metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_container_gauge_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a gauge metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_container_gauge_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("gauges.123456789abc$metric_name#tag_name1,tag_name2,tag_name3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

//-----------------------------------------------------------------------------
//-- parse_line() - container set metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a container set metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_container_set_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a container set metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_container_set_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a container set metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_container_set_container_id_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ("123456789abc", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a container set metric's
 * value.
 */
TEST(statsd_metric_test, parse_line_container_set_value)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_DOUBLE_EQ(42.0, metric.value());
}

/**
 * Ensure that parse_line() can correctly parse a container set metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_container_set_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_EQ(statsd_metric::type_t::SET, metric.type());
}

/**
 * Ensure that if no tags are included in a set metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_container_set_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name|42.000000|1563315016"));
	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a set metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_container_set_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name#tag_name=tag_value|42.000000|1563315016"));
	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a set metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_container_set_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("set.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a set metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_container_set_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("sets.123456789abc$metric_name#tag_name1,tag_name2,tag_name3|42.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

//-----------------------------------------------------------------------------
//-- parse_line() - container histogram metrics
//-----------------------------------------------------------------------------

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * timestamp.
 */
TEST(statsd_metric_test, parse_line_container_histogram_timestamp)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(1563315016, metric.timestamp());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * name.
 */
TEST(statsd_metric_test, parse_line_container_histogram_name)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ("metric_name", metric.name());
}

/**
 * Ensure that parse_line() leaves a container histogram metric's container_id
 * unset.
 */
TEST(statsd_metric_test, parse_line_container_histogram_container_id_is_blank)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ("123456789abc", metric.container_id());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * sum.
 */
TEST(statsd_metric_test, parse_line_container_histogram_sum)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(1.0, metric.sum());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * mean.
 */
TEST(statsd_metric_test, parse_line_container_histogram_mean)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(3.0, metric.mean());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * min.
 */
TEST(statsd_metric_test, parse_line_container_histogram_min)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(4.0, metric.min());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * max.
 */
TEST(statsd_metric_test, parse_line_container_histogram_max)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(5.0, metric.max());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * count.
 */
TEST(statsd_metric_test, parse_line_container_histogram_count)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(6.0, metric.count());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * stdev.
 */
TEST(statsd_metric_test, parse_line_container_histogram_stdev)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(7.0, metric.stdev());
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * p50, and the percentile(index) can read it.
 */
TEST(statsd_metric_test, parse_line_container_histogram_p50_percentile_v1)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(9.0, metric.percentile(50));
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * p50, and the percentile(percentile, value) can read it.
 */
TEST(statsd_metric_test, parse_line_container_histogram_p50_percentile_v2)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	double value = 142.5;
	ASSERT_TRUE(metric.percentile(50, value));
	ASSERT_DOUBLE_EQ(9.0, value);
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * p95, and the percentile(index) can read it.
 */
TEST(statsd_metric_test, parse_line_container_histogram_p95_percentile_v1)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(10.0, metric.percentile(95));
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * p95, and the percentile(percentile, value) can read it.
 */
TEST(statsd_metric_test, parse_line_container_histogram_p95_percentile_v2)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	double value = 142.5;
	ASSERT_TRUE(metric.percentile(95, value));
	ASSERT_DOUBLE_EQ(10.0, value);
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * p99, and the percentile(index) can read it.
 */
TEST(statsd_metric_test, parse_line_container_histogram_p99_percentile_v1)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_DOUBLE_EQ(11.0, metric.percentile(99));
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * p99, and the percentile(percentile, value) can read it.
 */
TEST(statsd_metric_test, parse_line_container_histogram_p99_percentile_v2)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	double value = 142.5;
	ASSERT_TRUE(metric.percentile(99, value));
	ASSERT_DOUBLE_EQ(11.0, value);
}

/**
 * Ensure that parse_line() can correctly parse a container histogram metric's
 * type.
 */
TEST(statsd_metric_test, parse_line_container_histogram_type)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(statsd_metric::type_t::HISTOGRAM, metric.type());
}

/**
 * Ensure that if no tags are included in a histogram metric, then parse_line
 * leave the tags empty.
 */
TEST(statsd_metric_test, parse_line_container_histogram_no_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name.sample_rate|13.000000|1563315016"));

	ASSERT_TRUE(metric.tags().empty());
}

/**
 * Ensure that if one tag is included in a histogram metric, then parse_line
 * correctly parses that tag.
 */
TEST(statsd_metric_test, parse_line_container_histogram_one_tag)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name=tag_value.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(1, metric.tags().size());
	ASSERT_EQ("tag_value", metric.tags().find("tag_name")->second);
}

/**
 * Ensure that if multiple tags are included in a histogram metric, then
 * parse_line correctly parses all of the tags.
 */
TEST(statsd_metric_test, parse_line_container_histogram_multiple_tags)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1=tag_value1,tag_name2=tag_value2,tag_name3=tag_value3.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("tag_value1", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("tag_value2", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("tag_value3", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if multiple tags are included in a histogram metric, then
 * parse_line correctly parses all of the tags with no values.
 */
TEST(statsd_metric_test, parse_line_container_histogram_multiple_tags_no_values)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sample_rate|13.000000|1563315016"));

	ASSERT_EQ(3, metric.tags().size());
	ASSERT_EQ("", metric.tags().find("tag_name1")->second);
	ASSERT_EQ("", metric.tags().find("tag_name2")->second);
	ASSERT_EQ("", metric.tags().find("tag_name3")->second);
}

/**
 * Ensure that if the timestamp differs between two different histogram
 * metric lines, the call to parse_line with the timestamp that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_container_histogram_mixed_timestamps_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315017"));
}

/**
 * Ensure that if the type differs between two different histogram
 * metric lines, the call to parse_line with the type that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_container_histogram_mixed_types_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("sets.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));
}

/**
 * Ensure that if the metric name differs between two different histogram
 * metric lines, the call to parse_line with the name that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_container_histogram_mixed_names_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name1#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.123456789abc$metric_name2#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));

}

/**
 * Ensure that if the container id differs between two different histogram
 * metric lines, the call to parse_line with the container id that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_container_histogram_mixed_container_ids_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.123456789abd$metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));

}

/**
 * Ensure that if the tags differs between two different histogram
 * metric lines, the call to parse_line with the tags that differs
 * fails.
 */
TEST(statsd_metric_test, parse_line_container_histogram_mixed_tags_fails)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_FALSE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2.sum_sq|2.000000|1563315016"));

}

//-----------------------------------------------------------------------------
//-- parse_line() - parse failures
//-----------------------------------------------------------------------------

TEST(statsd_metric_test, parse_line_failure)
{
	statsd_metric metric;

	ASSERT_THROW(metric.parse_line("this is not a metric"),
	             statsd_metric::parse_exception);
}

//-----------------------------------------------------------------------------
//-- {de,}sanitize_container_id
//-----------------------------------------------------------------------------

/**
 * Ensure that sanitize_container_id() converts all ':' to '+'
 */
TEST(statsd_metric_test, sanitize_container_id)
{
	const std::string original = "1234:5678:9abc";

	ASSERT_EQ("1234+5678+9abc", statsd_metric::sanitize_container_id(original));
}

/**
 * Ensure that sanitize_container_id() converts all '+' to ':'
 */
TEST(statsd_metric_test, desanitize_container_id)
{
	const std::string original = "1234+5678+9abc";

	ASSERT_EQ("1234:5678:9abc", statsd_metric::desanitize_container_id(original));
}

//-----------------------------------------------------------------------------
//-- type_to_string
//-----------------------------------------------------------------------------

TEST(statsd_metric_test, type_to_string_NONE)
{
	ASSERT_EQ("NONE", statsd_metric::type_to_string(statsd_metric::type_t::NONE));
}

TEST(statsd_metric_test, type_to_string_COUNT)
{
	ASSERT_EQ("COUNT", statsd_metric::type_to_string(statsd_metric::type_t::COUNT));
}

TEST(statsd_metric_test, type_to_string_HISTOGRAM)
{
	ASSERT_EQ("HISTOGRAM", statsd_metric::type_to_string(statsd_metric::type_t::HISTOGRAM));
}

TEST(statsd_metric_test, type_to_string_GAUGE)
{
	ASSERT_EQ("GAUGE", statsd_metric::type_to_string(statsd_metric::type_t::GAUGE));
}

TEST(statsd_metric_test, type_to_string_SET)
{
	ASSERT_EQ("SET", statsd_metric::type_to_string(statsd_metric::type_t::SET));
}

TEST(statsd_metric_test, type_to_string_INVALID)
{
	// Normally avoid using C-style casts in C++, but given the horrible
	// thing we're doing here, the C-style cast is the only thing that will
	// do what we need (reinterpret_cast, didn't work here).
	//
	// This is an excellent example of why C-style cases ought to be
	// avoided :)
	ASSERT_EQ("??", statsd_metric::type_to_string((statsd_metric::type_t) -42));
}

//-----------------------------------------------------------------------------
//-- to_debug_string
//-----------------------------------------------------------------------------

TEST(statsd_metric_test, to_debug_string)
{
	statsd_metric metric;

	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum|1.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sum_sq|2.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.mean|3.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.lower|4.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.upper|5.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.count|6|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.stdev|7.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.median|8.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.p50|9.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.p95|10.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.p99|11.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.rate|12.000000|1563315016"));
	ASSERT_TRUE(metric.parse_line("timers.123456789abc$metric_name#tag_name1,tag_name2,tag_name3.sample_rate|13.000000|1563315016"));

	const std::string expected =
		"-- statsd metric --------------------------------\n"
		"timestamp:      1563315016\n"
		"name:           metric_name\n"
		"container_id:   123456789abc\n"
		"type:           HISTOGRAM\n"
		"full id parsed: true\n"
		"value:          0\n"
		"sum:            1\n"
		"mean:           3\n"
		"min:            4\n"
		"max:            5\n"
		"count:          6\n"
		"stdev:          7\n"
		"tags: {\n"
		"  [tag_name1, ]\n"
		"  [tag_name2, ]\n"
		"  [tag_name3, ]\n"
		"}\n"
		"percentiles: {\n"
		"  [50, 9]\n"
		"  [95, 10]\n"
		"  [99, 11]\n"
		"}\n";

	ASSERT_EQ(expected, metric.to_debug_string());
}
