/**
 * @file
 *
 * Unit tests for scoped_metric_store.
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
 * Ensure that scoped_metric_store saves the state of the metric_store on
 * creation and restores the state of the metric_store on destruction.
 */
TEST(scoped_metric_store_test, works)
{
	metric_store::store(nullptr);

	{
		scoped_metric_store scoped_store;

		// Make sure it didn't modify the store on creation
		ASSERT_EQ(nullptr, metric_store::get());

		std::shared_ptr<draiosproto::metrics> metrics =
			std::make_shared<draiosproto::metrics>();

		metric_store::store(metrics);
	}

	// Make sure it restored the store on destruction
	ASSERT_EQ(nullptr, metric_store::get());
}

