#pragma once

#include <atomic>
#include <memory>
#include <vector>
#include <Poco/ThreadPool.h>
#include "watchdog_runnable.h"

namespace dragent
{

/**
 * A watchdog runnable pool that can be queried for whether the
 * runnables are healthy.
 */
class watchdog_runnable_pool
{
public:
	/**
	 * Start the given runnable. This does NOT pass ownership to the pool and
	 * the pool will not destroy the runnables on destruction.
	 *
	 * @param watchdog_runnable runnable to start
	 * @param timeout_s number of seconds before runnable is
	 *      	    declared unhealthy
	 *
	 * @throws many POCO exceptions
	 */
	void start(watchdog_runnable& to_start, uint64_t timeout_s);

	/**
	 * Start the given runnable. This does pass ownership to the pool and the
	 * pool can destroy the runnable on destruction.
	 *
	 * @param watchdog_runnable runnable to start
	 * @param timeout_s number of seconds before runnable is
	 *      	    declared unhealthy
	 *
	 * @throws many POCO exceptions
	 */
	void start(const std::shared_ptr<watchdog_runnable>& to_start, uint64_t timeout_s);

	/**
	 * Stop all runnables
	 */
	void stop_all();

	struct unhealthy_runnable
	{
		const watchdog_runnable& runnable;
		watchdog_runnable::health health;
		int64_t since_last_heartbeat_ms;

	};
	typedef std::vector<unhealthy_runnable> unhealthy_runnables;

	/**
	 * @return a list of all runnables that are unhealthy
	 */
	unhealthy_runnables unhealthy_list() const;

	/**
	 * Log a report on all runnables and how long since they have
	 * checked in.
	 */
	void log_report() const;

private:

	std::vector<std::reference_wrapper<watchdog_runnable>> m_runnables;

	std::vector<std::shared_ptr<watchdog_runnable>> m_storage;

};

} // namespace dragent

