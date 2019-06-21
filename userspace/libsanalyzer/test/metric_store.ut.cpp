/**
 * @file
 *
 * Unit tests for namespace metric_store.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "draios.pb.h"
#include "metric_store.h"
#include "scoped_metric_store.h"
#include <memory>
#include <gtest.h>

using namespace libsanalyzer;
using test_helpers::scoped_metric_store;

/**
 * Ensure that the metric_store initially has no metrics.
 */
TEST(metric_store_test, initial_state_should_be_nullptr)
{
	scoped_metric_store scoped_store;

	ASSERT_EQ(nullptr, metric_store::get());
}

/**
 * Ensure that set/get a non-nullptr metric saves/returns the expected metrics
 */
TEST(metric_store_test, set_get_non_nullptr)
{
	scoped_metric_store scoped_store;

	const std::shared_ptr<draiosproto::metrics> metrics =
		std::make_shared<draiosproto::metrics>();

	metric_store::store(metrics);

	ASSERT_EQ(metrics.get(), metric_store::get().get());
}

/**
 * Ensure that set/get a nullptr metric saves/returns the expected metrics
 */
TEST(metric_store_test, set_get_nullptr)
{
	scoped_metric_store scoped_store;

	// nullptr by default
	const std::shared_ptr<draiosproto::metrics> metrics;

	metric_store::store(metrics);

	ASSERT_EQ(metrics.get(), metric_store::get().get());
}
