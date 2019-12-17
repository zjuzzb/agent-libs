/**
 * @file
 *
 * Unit tests for metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "analyzer_flush_message.h"
#include "uncompressed_sample_handler.h"
#include "metric_serializer.h"
#include "dragent_message_queues.h"
#include "protobuf_metric_serializer.h"
#include "scoped_config.h"
#include "protobuf_compression.h"
#include <memory>
#include <gtest.h>
#include <stdint.h>

class test_helper
{
public:
	static uncompressed_sample_handler& get_sample_handler(dragent::metric_serializer& ms)
	{
		return ms.m_uncompressed_sample_handler;
	}
};

class capture_stats_source;

using namespace dragent;

namespace
{
const uint32_t max_queue_size = 32;
uncompressed_sample_handler_dummy g_sample_handler;
flush_queue g_fqueue(max_queue_size);
protocol_queue g_pqueue(max_queue_size);
}

/**
 * Ensure that the constructed object is in the expected initial state.
 */
TEST(metric_serializer_test, initial_state)
{
	std::shared_ptr<capture_stats_source> stats_source = nullptr;
	auto compressor = null_protobuf_compressor::get();

	std::unique_ptr<metric_serializer> s(
	            new protobuf_metric_serializer(stats_source,
	                                           ".",
	                                           g_sample_handler,
	                                           &g_fqueue,
	                                           &g_pqueue,
	                                           compressor));

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

	std::shared_ptr<capture_stats_source> stats_source = nullptr;

	auto compressor = null_protobuf_compressor::get();
	auto new_compressor = gzip_protobuf_compressor::get(-1);

	std::unique_ptr<metric_serializer> s(
	    new protobuf_metric_serializer(stats_source,
	                                   root_dir,
	                                   g_sample_handler,
	                                   &g_fqueue,
	                                   &g_pqueue,
	                                   compressor));

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

	// Check that we can change compression
	bool ret = s->set_compression(new_compressor);
	ASSERT_TRUE(ret);
}
