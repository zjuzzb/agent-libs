/**
 * @file
 *
 * Interface to scoped_metric_store.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include <memory>

namespace draiosproto { class metrics; }

namespace test_helpers
{

/**
 * Scoped wrapper around the metric store.  Saves the state on construction;
 * restores the state on destruction.
 */
class scoped_metric_store
{
public:
	scoped_metric_store();
	~scoped_metric_store();

private:
	std::shared_ptr<const draiosproto::metrics> m_old_metrics;
};

} // namespace test_helpers
