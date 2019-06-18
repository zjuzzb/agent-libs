/**
 * @file
 *
 * Unit tests for null_statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "null_statsd_emitter.h"
#include "draios.pb.h"
#include <google/protobuf/util/message_differencer.h>
#include <gtest.h>

using libsanalyzer::null_statsd_emitter;

/**
 * Exercise the null fetch -- there's nothing to check for here.
 */
TEST(null_statsd_emitter_test, fetch_metrics_does_nothing)
{
	null_statsd_emitter emitter;

	emitter.fetch_metrics(0);
}

/**
 * Ensure that emit() for the host statsd data modifies neither the host
 * nor the metric parameters.
 */
TEST(null_statsd_emitter_test, emit_host_does_nothing)
{
	null_statsd_emitter emitter;

	::draiosproto::host host;
	const ::draiosproto::host expected_host;

	::draiosproto::statsd_info metrics;
	const ::draiosproto::statsd_info expected_metrics;

	emitter.emit(&host, &metrics);

	ASSERT_TRUE(::google::protobuf::util::MessageDifferencer::Equals(
			expected_host,
			host));

	ASSERT_TRUE(::google::protobuf::util::MessageDifferencer::Equals(
			expected_metrics,
			metrics));
}

/**
 * Ensure that emit() for a container's statsd data does not modify the
 * container parameter.  Ensure that the method returns the same limit as
 * provided.
 */
TEST(null_statsd_emitter_test, emit_container_does_nothing)
{
	const unsigned expected_limit = 42;
	const std::string container_id = "aaabbbcccddd";
	const std::string container_name = "some_name";
	null_statsd_emitter emitter;

	::draiosproto::container container;
	const ::draiosproto::container expected_container;

	const unsigned limit = emitter.emit(container_id,
	                                    container_name,
	                                    &container,
	                                    expected_limit);

	ASSERT_TRUE(::google::protobuf::util::MessageDifferencer::Equals(
			expected_container,
			container));
	ASSERT_EQ(expected_limit, limit);
}
