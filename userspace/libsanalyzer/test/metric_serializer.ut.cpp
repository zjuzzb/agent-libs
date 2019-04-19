/**
 * @file
 *
 * Unit tests for metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_serializer.h"
#include "analyzer_callback_interface.h"
#include "config.h"
#include "internal_metrics.h"
#include "metric_serializer_factory.h"
#include <memory>
#include <gtest.h>

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
	const bool EMIT_METRICS_TO_FILE = false;
	const bool COMPRESS_METRICS = false;
	const std::string METRICS_DIRECTORY = "./";

	sinsp_configuration config;

	config.set_emit_metrics_to_file(EMIT_METRICS_TO_FILE);
	config.set_compress_metrics(COMPRESS_METRICS);

	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics(new internal_metrics());

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
						 &config));

	ASSERT_NE(s.get(), nullptr);
	ASSERT_EQ(int_metrics.get(), s->get_internal_metrics().get());
	ASSERT_EQ(nullptr, s->get_sample_callback());
	ASSERT_EQ(EMIT_METRICS_TO_FILE, s->get_emit_metrics_to_file());
	ASSERT_EQ(COMPRESS_METRICS, s->get_compress_metrics());
	ASSERT_EQ(METRICS_DIRECTORY, s->get_metrics_directory());
}


/**
 * Ensure that update_configuration() updates the changes the values
 * of the config values of interest.
 */
TEST(metric_serializer_test, update_configuration)
{
	bool emit_metrics_to_file = false;
	bool compress_metrics = false;
	std::string metrics_directory = "./";

	sinsp_configuration config;

	config.set_emit_metrics_to_file(emit_metrics_to_file);
	config.set_compress_metrics(compress_metrics);

	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics(new internal_metrics());

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
						 &config));

	// Make sure that build() passed the values along as expected
	ASSERT_EQ(emit_metrics_to_file, s->get_emit_metrics_to_file());
	ASSERT_EQ(compress_metrics, s->get_compress_metrics());
	ASSERT_EQ(metrics_directory, s->get_metrics_directory());

	emit_metrics_to_file = true;
	compress_metrics = true;
	metrics_directory = "/tmp/";

	sinsp_configuration new_config;

	new_config.set_emit_metrics_to_file(emit_metrics_to_file);
	new_config.set_compress_metrics(compress_metrics);
	new_config.set_metrics_directory(metrics_directory);

	s->update_configuration(&new_config);

	// Make sure that update_configuration() updates the values
	ASSERT_EQ(emit_metrics_to_file, s->get_emit_metrics_to_file());
	ASSERT_EQ(compress_metrics, s->get_compress_metrics());
	ASSERT_EQ(metrics_directory, s->get_metrics_directory());
}

/**
 * Ensure that set_internal_metrics updates the internal_metrics.
 */
TEST(metric_serializer_test, set_internal_metrics)
{
	capture_stats_source* stats_source = nullptr;
	internal_metrics::sptr_t int_metrics(new internal_metrics());
	internal_metrics::sptr_t int_metrics2(new internal_metrics());
	sinsp_configuration config;

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
		                                 &config));


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
	sinsp_configuration config;

	std::unique_ptr<metric_serializer> s(
		metric_serializer_factory::build(stats_source,
		                                 int_metrics,
		                                 &config));


	s->set_sample_callback(&cb);
	ASSERT_EQ(&cb, s->get_sample_callback());
}
