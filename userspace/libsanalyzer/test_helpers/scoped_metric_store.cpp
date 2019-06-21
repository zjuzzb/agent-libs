/**
 * @file
 *
 * Implementation of scoped_metric_store.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_metric_store.h"
#include "metric_store.h"

namespace test_helpers
{

scoped_metric_store::scoped_metric_store():
	m_old_metrics(libsanalyzer::metric_store::get())
{ }

scoped_metric_store::~scoped_metric_store()
{
	libsanalyzer::metric_store::store(m_old_metrics);
}

} // namespace test_helpers
