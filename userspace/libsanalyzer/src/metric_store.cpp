/**
 * @file
 *
 * Implementation of namespace metric_store.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metric_store.h"
#include <memory>
#include <mutex>

namespace
{

/**
 * We want to avoid having static mutexes, etc. because some of our tests
 * fork() then terminate, and if the mutex is in a bad state on exit we
 * crash.  As a result, we'll wrap the mutex in a function and dynamically
 * allocate it.
 */
std::mutex& get_mutex()
{
	static std::mutex* mutex = nullptr;

	if(mutex == nullptr)
	{
		mutex = new std::mutex();
	}

	return *mutex;
}

/** Pointer to the last complete protobuf. */
std::shared_ptr<const draiosproto::metrics> s_metrics;

} // end namespace


namespace libsanalyzer
{

void metric_store::store(const std::shared_ptr<const draiosproto::metrics>& metrics)
{
	std::unique_lock<std::mutex> lock(get_mutex());

	s_metrics = metrics;
}

std::shared_ptr<const draiosproto::metrics> metric_store::get()
{
	std::unique_lock<std::mutex> lock(get_mutex());

	return s_metrics;
}

} // namespace libsanalyzer
