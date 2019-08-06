/**
 * @file
 *
 * Unit tests for statsd_emitter_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_limits.h"
#include "null_statsd_emitter.h"
#include "statsd_emitter.h"
#include "statsd_emitter_factory.h"
#include "statsite_proxy.h"
#include <gtest.h>

using libsanalyzer::statsd_emitter;
using libsanalyzer::null_statsd_emitter;

namespace
{

/**
 * A do-nothing realization of the statsd_stats_source interface.
 */
class null_statsd_stats_source : public statsd_stats_source
{
public:
	/** Does nothing.  Returns an empty map. */
	statsd_stats_source::container_statsd_map read_metrics(
			metric_limits::cref_sptr_t ml = nullptr) override
	{
		return statsd_stats_source::container_statsd_map();
	}
};

} // namespace

/**
 * Ensure that statsd_emitter_factory::create() returns non-nullptr by default.
 */
TEST(statsd_emitter_factory_test, create_returns_concrete_emitter)
{
	statsd_stats_source::ptr source = std::make_shared<null_statsd_stats_source>();
	metric_limits::sptr_t limits;

	statsd_emitter::ptr emitter = libsanalyzer::statsd_emitter_factory::create(
			source,
			limits);

	ASSERT_NE(emitter.get(), nullptr);
}

/**
 * Ensure that if an emitter has been injected, statsd_emitter_factory::create()
 * returns that emitter.
 */
TEST(statsd_emitter_factory_test, inject_injects_correct_emitter)
{
	statsd_emitter::ptr expected_emitter(new null_statsd_emitter());
	libsanalyzer::statsd_emitter_factory::inject(expected_emitter);

	statsd_stats_source::ptr source = std::make_shared<null_statsd_stats_source>();
	metric_limits::sptr_t limits;

	statsd_emitter::ptr emitter = libsanalyzer::statsd_emitter_factory::create(
			source,
			limits);

	ASSERT_EQ(expected_emitter.get(), emitter.get());
}

/**
 * Ensure that if an emitter has been injected, statsd_emitter_factory::create()
 * returns that emitter only on the first call; subsequent calls to create
 * should not return the same emitter.
 */
TEST(statsd_emitter_factory_test, injected_emitter_is_not_returned_multiple_times)
{
	statsd_emitter::ptr original_emitter(new null_statsd_emitter());
	libsanalyzer::statsd_emitter_factory::inject(original_emitter);

	statsd_stats_source::ptr source = std::make_shared<null_statsd_stats_source>();
	metric_limits::sptr_t limits;

	statsd_emitter::ptr emitter = libsanalyzer::statsd_emitter_factory::create(
			source,
			limits);

	// The second call to create() should not return the same emitter.
	emitter = libsanalyzer::statsd_emitter_factory::create(
			source,
			limits);

	ASSERT_NE(original_emitter.get(), emitter.get());
}
