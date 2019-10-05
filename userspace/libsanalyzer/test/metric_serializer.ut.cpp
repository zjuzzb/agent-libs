/**
 * @file
 *
 * Unit tests for metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "uncompressed_sample_handler.h"
#include "metric_serializer.h"
#include "internal_metrics.h"
#include "metric_serializer_factory.h"
#include <memory>
#include <gtest.h>
#include "scoped_config.h"

class test_helper
{
public:
	static uncompressed_sample_handler& get_sample_handler(libsanalyzer::metric_serializer& ms)
	{
		return ms.m_uncompressed_sample_handler;
	}
};

class capture_stats_source;

using namespace libsanalyzer;

namespace
{
uncompressed_sample_handler_dummy g_sample_handler;
}

/**
 * Ensure that the factory method returns a concrete metric_serializer and
 * that that object is in the expected initial state.
 */
TEST(metric_serializer_test, initial_state)
{
	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
						 ".",
						 g_sample_handler));

	ASSERT_NE(s.get(), nullptr);
	ASSERT_EQ(&g_sample_handler, &test_helper::get_sample_handler(*s));

	// non-null metrics dir implies emit to file
	ASSERT_EQ(metric_serializer::c_metrics_dir.get_value() != "", s->get_emit_metrics_to_file());
}


/**
 * ensure we deal with configuring the metrics directory correctly
 */
TEST(metric_serializer_test, configuration)
{	
	const std::string root_dir = "/foo";
	const std::string metrics_directory = "/tmp";
	test_helpers::scoped_config<std::string> config("metricsfile.location", metrics_directory);

	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
						 root_dir,
						 g_sample_handler));

	// Make sure that update_configuration() updates the values
	ASSERT_TRUE(s->get_emit_metrics_to_file());
	ASSERT_EQ("/foo/tmp/", s->get_metrics_directory());

	// Check that the set_metrics_directory API works
	s->set_metrics_directory("/bar/");
	ASSERT_TRUE(s->get_emit_metrics_to_file());
	ASSERT_EQ("/bar/", s->get_metrics_directory());

	// Check that we can disable it
	s->set_metrics_directory("");
	ASSERT_FALSE(s->get_emit_metrics_to_file());
	ASSERT_EQ("", s->get_metrics_directory());
}
