/**
 * @file
 *
 * Unit tests for metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_serializer.h"
#include "analyzer_callback_interface.h"
#include "internal_metrics.h"
#include "metric_serializer_factory.h"
#include <memory>
#include <gtest.h>
#include "scoped_config.h"

class capture_stats_source;

using namespace libsanalyzer;

namespace
{

/**
 * Do-nothing realization of analyzer_callback_interface.
 */
class null_analyzer_callback_interface : public analyzer_callback_interface
{
public:
	void sinsp_analyzer_data_ready(const uint64_t ts_ns,
	                               const uint64_t nevts,
	                               const uint64_t num_drop_events,
	                               draiosproto::metrics* const metrics,
	                               const uint32_t sampling_ratio,
	                               const double analyzer_cpu_pct,
	                               const double flush_cpu_cpt,
	                               const uint64_t analyzer_flush_duration_ns,
	                               const uint64_t num_suppressed_threads) override
	{ }

	void audit_tap_data_ready(const uint64_t ts_ns,
	                          const tap::AuditLog* const audit_log) override
	{ }
};

} // end namespace

/**
 * Ensure that the factory method returns a concrete metric_serializer and
 * that that object is in the expected initial state.
 */
TEST(metric_serializer_test, initial_state)
{
	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics(new internal_metrics());

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
						 "."));

	ASSERT_NE(s.get(), nullptr);
	ASSERT_EQ(int_metrics.get(), s->get_internal_metrics().get());
	ASSERT_EQ(nullptr, s->get_sample_callback());

	// non-null metrics dir implies emit to file
	ASSERT_EQ(metric_serializer::c_metrics_dir.get() != "", s->get_emit_metrics_to_file());
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
	internal_metrics::sptr_t int_metrics(new internal_metrics());

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
						 root_dir));

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

/**
 * Ensure that set_internal_metrics updates the internal_metrics.
 */
TEST(metric_serializer_test, set_internal_metrics)
{
	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics(new internal_metrics());
	internal_metrics::sptr_t int_metrics2(new internal_metrics());

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
		                                 ""));


	s->set_internal_metrics(int_metrics2);
	ASSERT_EQ(int_metrics2.get(), s->get_internal_metrics().get());
}

/**
 * Ensure that set_sample_callback updates the sample callback.
 */
TEST(metric_serializer_test, set_sample_callback)
{
	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics(new internal_metrics());
	null_analyzer_callback_interface cb;

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
		                                 ""));


	s->set_sample_callback(&cb);
	ASSERT_EQ(&cb, s->get_sample_callback());
}
