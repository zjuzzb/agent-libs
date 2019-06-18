/**
 * @file
 *
 * Unit tests for statsite_statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "draios.pb.h"
#include "dummy_statsd_stats_source.h"
#include "metric_limits.h"
#include "scoped_config.h"
#include "statsite_statsd_emitter.h"
#include <google/protobuf/util/message_differencer.h>
#include <gtest.h>

using libsanalyzer::statsite_statsd_emitter;
using test_helpers::dummy_statsd_stats_source;
using test_helpers::scoped_config;

/**
 * Ensure that fetch_metrics() + emit for the host writes the expected counter
 * metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_host_counter_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::host host;
	::draiosproto::statsd_info metrics;

	source->add_counter(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	emitter.emit(&host, &metrics);

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_sent());

	ASSERT_EQ(1, metrics.statsd_metrics_size());
	ASSERT_EQ(name, metrics.statsd_metrics(0).name());
	ASSERT_EQ(2, metrics.statsd_metrics(0).tags_size());
	ASSERT_EQ("a", metrics.statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", metrics.statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", metrics.statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", metrics.statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_COUNT, metrics.statsd_metrics(0).type());
	ASSERT_EQ(value, metrics.statsd_metrics(0).value());
}

/**
 * Ensure that fetch_metrics() + emit for a container writes the expected
 * counter metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_container_counter_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "aaabbbcccddd";
	const std::string container_name = "bobs_container";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;
	const unsigned limit = 1000;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::container container;

	source->add_counter(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	ASSERT_EQ(limit - 1,
	          emitter.emit(container_id, container_name, &container, limit));

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_sent());
	ASSERT_TRUE(container.protos().has_statsd());
	ASSERT_EQ(name, container.protos().statsd().statsd_metrics(0).name());
	ASSERT_EQ(2, container.protos().statsd().statsd_metrics(0).tags_size());
	ASSERT_EQ("a", container.protos().statsd().statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", container.protos().statsd().statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", container.protos().statsd().statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", container.protos().statsd().statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_COUNT,
	          container.protos().statsd().statsd_metrics(0).type());
	ASSERT_EQ(value, container.protos().statsd().statsd_metrics(0).value());
}

/**
 * Ensure that fetch_metrics() + emit for the host writes the expected gauge
 * metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_host_gauge_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::host host;
	::draiosproto::statsd_info metrics;

	source->add_gauge(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	emitter.emit(&host, &metrics);

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_sent());

	ASSERT_EQ(1, metrics.statsd_metrics_size());
	ASSERT_EQ(name, metrics.statsd_metrics(0).name());
	ASSERT_EQ(2, metrics.statsd_metrics(0).tags_size());
	ASSERT_EQ("a", metrics.statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", metrics.statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", metrics.statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", metrics.statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_GAUGE, metrics.statsd_metrics(0).type());
	ASSERT_EQ(value, metrics.statsd_metrics(0).value());
}

/**
 * Ensure that fetch_metrics() + emit for a container writes the expected
 * gauge metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_container_gauge_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "aaabbbcccddd";
	const std::string container_name = "bobs_container";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;
	const unsigned limit = 1000;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::container container;

	source->add_gauge(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	ASSERT_EQ(limit - 1,
	          emitter.emit(container_id, container_name, &container, limit));

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_sent());
	ASSERT_TRUE(container.protos().has_statsd());
	ASSERT_EQ(name, container.protos().statsd().statsd_metrics(0).name());
	ASSERT_EQ(2, container.protos().statsd().statsd_metrics(0).tags_size());
	ASSERT_EQ("a", container.protos().statsd().statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", container.protos().statsd().statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", container.protos().statsd().statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", container.protos().statsd().statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_GAUGE,
	          container.protos().statsd().statsd_metrics(0).type());
	ASSERT_EQ(value, container.protos().statsd().statsd_metrics(0).value());
}

/**
 * Ensure that fetch_metrics() + emit for the host writes the expected set
 * metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_host_set_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::host host;
	::draiosproto::statsd_info metrics;

	source->add_set(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	emitter.emit(&host, &metrics);

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_sent());

	ASSERT_EQ(1, metrics.statsd_metrics_size());
	ASSERT_EQ(name, metrics.statsd_metrics(0).name());
	ASSERT_EQ(2, metrics.statsd_metrics(0).tags_size());
	ASSERT_EQ("a", metrics.statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", metrics.statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", metrics.statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", metrics.statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_SET, metrics.statsd_metrics(0).type());
	ASSERT_EQ(value, metrics.statsd_metrics(0).value());
}

/**
 * Ensure that fetch_metrics() + emit for a container writes the expected
 * set metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_container_set_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "aaabbbcccddd";
	const std::string container_name = "bobs_container";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;
	const unsigned limit = 1000;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::container container;

	source->add_set(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	ASSERT_EQ(limit - 1, emitter.emit(container_id, container_name, &container, limit));

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_sent());
	ASSERT_TRUE(container.protos().has_statsd());
	ASSERT_EQ(name, container.protos().statsd().statsd_metrics(0).name());
	ASSERT_EQ(2, container.protos().statsd().statsd_metrics(0).tags_size());
	ASSERT_EQ("a", container.protos().statsd().statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", container.protos().statsd().statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", container.protos().statsd().statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", container.protos().statsd().statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_SET,
	          container.protos().statsd().statsd_metrics(0).type());
	ASSERT_EQ(value, container.protos().statsd().statsd_metrics(0).value());
}

/**
 * Ensure that fetch_metrics() + emit for the host writes the expected histogram
 * metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_host_histogram_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::host host;
	::draiosproto::statsd_info metrics;

	source->add_histogram(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	emitter.emit(&host, &metrics);

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_sent());

	ASSERT_EQ(1, metrics.statsd_metrics_size());
	ASSERT_EQ(name, metrics.statsd_metrics(0).name());
	ASSERT_EQ(2, metrics.statsd_metrics(0).tags_size());
	ASSERT_EQ("a", metrics.statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", metrics.statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", metrics.statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", metrics.statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_HISTOGRAM, metrics.statsd_metrics(0).type());
	ASSERT_EQ(value, metrics.statsd_metrics(0).sum());
	ASSERT_EQ(value, metrics.statsd_metrics(0).min());
	ASSERT_EQ(value, metrics.statsd_metrics(0).max());
	ASSERT_EQ(1, metrics.statsd_metrics(0).count());

	ASSERT_EQ(3, metrics.statsd_metrics(0).percentile_size());

	ASSERT_EQ(50, metrics.statsd_metrics(0).percentile(0).percentile());
	ASSERT_EQ(static_cast<int>(value),
	          metrics.statsd_metrics(0).percentile(0).value());

	ASSERT_EQ(95, metrics.statsd_metrics(0).percentile(1).percentile());
	ASSERT_EQ(static_cast<int>(value),
	          metrics.statsd_metrics(0).percentile(1).value());

	ASSERT_EQ(99, metrics.statsd_metrics(0).percentile(2).percentile());
	ASSERT_EQ(static_cast<int>(value),
	          metrics.statsd_metrics(0).percentile(2).value());
}

/**
 * Ensure that fetch_metrics() + emit for a container writes the expected
 * histogram metrics to the given protobufs.
 */
TEST(statsite_statsd_emitter_test, emit_container_histogram_metric)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "aaabbbcccddd";
	const std::string container_name = "bobs_container";
	const bool security_enabled = true;
	const unsigned limit = 1000;
	const metric_limits::sptr_t limits;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::container container;

	source->add_histogram(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	ASSERT_EQ(limit - 1,
	          emitter.emit(container_id, container_name, &container, limit));

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_sent());

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_sent());
	ASSERT_TRUE(container.protos().has_statsd());
	ASSERT_EQ(name, container.protos().statsd().statsd_metrics(0).name());
	ASSERT_EQ(2, container.protos().statsd().statsd_metrics(0).tags_size());
	ASSERT_EQ("a", container.protos().statsd().statsd_metrics(0).tags(0).key());
	ASSERT_EQ("b", container.protos().statsd().statsd_metrics(0).tags(0).value());
	ASSERT_EQ("c", container.protos().statsd().statsd_metrics(0).tags(1).key());
	ASSERT_EQ("d", container.protos().statsd().statsd_metrics(0).tags(1).value());
	ASSERT_EQ(draiosproto::STATSD_HISTOGRAM,
	          container.protos().statsd().statsd_metrics(0).type());
	ASSERT_EQ(value, container.protos().statsd().statsd_metrics(0).sum());
	ASSERT_EQ(value, container.protos().statsd().statsd_metrics(0).min());
	ASSERT_EQ(value, container.protos().statsd().statsd_metrics(0).max());
	ASSERT_EQ(1, container.protos().statsd().statsd_metrics(0).count());

	ASSERT_EQ(3, container.protos().statsd().statsd_metrics(0).percentile_size());

	ASSERT_EQ(50, container.protos().statsd().statsd_metrics(0).percentile(0).percentile());
	ASSERT_EQ(static_cast<int>(value),
	          container.protos().statsd().statsd_metrics(0).percentile(0).value());

	ASSERT_EQ(95, container.protos().statsd().statsd_metrics(0).percentile(1).percentile());
	ASSERT_EQ(static_cast<int>(value),
	          container.protos().statsd().statsd_metrics(0).percentile(1).value());

	ASSERT_EQ(99, container.protos().statsd().statsd_metrics(0).percentile(2).percentile());
	ASSERT_EQ(static_cast<int>(value),
	          container.protos().statsd().statsd_metrics(0).percentile(2).value());
}

/**
 * Ensure that trying to add more than the configured limit statsd metrics for
 * the host fails.
 */
TEST(statsite_statsd_emitter_test, emit_host_cannot_exceed_limit)
{
	scoped_config<int> statd_limit("statsd.limit", 0);

	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "";
	const bool security_enabled = false;
	const metric_limits::sptr_t limits;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::host host;
	::draiosproto::statsd_info metrics;
	const ::draiosproto::statsd_info expected_metrics;

	source->add_counter(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	emitter.emit(&host, &metrics);

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, host.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(host.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(0, host.mutable_resource_counters()->statsd_sent());

	ASSERT_TRUE(::google::protobuf::util::MessageDifferencer::Equals(
			expected_metrics,
			metrics));
}

/**
 * Ensure that trying to add more than the configured limit statsd metrics for
 * containers fails.
 */
TEST(statsite_statsd_emitter_test, emit_container_cannot_exceed_limit)
{
	const std::string name = "some_metric";
	const double value = 42.7;
	const uint64_t ts = 8123456789LL;
	const std::string container_id = "aaabbbcccddd";
	const std::string container_name = "bobs_container";
	const bool security_enabled = true;
	const metric_limits::sptr_t limits;
	const unsigned limit = 0;

	std::shared_ptr<dummy_statsd_stats_source> source =
		std::make_shared<dummy_statsd_stats_source>();
	::draiosproto::container container;

	source->add_counter(name, value, ts, container_id, {"a:b", "c:d"});

	statsite_statsd_emitter emitter(security_enabled, source, limits);

	emitter.fetch_metrics(ts);
	ASSERT_EQ(limit,
	          emitter.emit(container_id, container_name, &container, limit));

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_total());
	ASSERT_EQ(1, container.mutable_resource_counters()->statsd_total());

	ASSERT_TRUE(container.mutable_resource_counters()->has_statsd_sent());
	ASSERT_EQ(0, container.mutable_resource_counters()->statsd_sent());
}
