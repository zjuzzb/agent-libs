#pragma once

#include <atomic>
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
	 * Start the given runnable. This does not pass ownership and the
	 * pool will not destroy the runnables on
	 * destruction.
	 *
	 * @param watchdog_runnable runnable to start
	 * @param timeout_s number of seconds before runnable is
	 *      	    declared unhealthy
	 *
	 * @throws many POCO exceptions
	 */
	void start(watchdog_runnable& toStart, uint64_t timeout_s);

	/**
	 * Stop all runnables
	 */
	void stop_all();

	struct hung_runnable
	{
		const watchdog_runnable& hung;
		int64_t since_last_heartbeat_ms;

	};
	typedef std::vector<hung_runnable> hung_runnables;
	/**
	 * @return a list of all runnables that are unhealthy
	 */
	hung_runnables unhealthy_runnables() const;

private:

	// The watchdog_runnable_pool does not own the runnables and will
	// not destroy them when the watchdog_runnable_pool destructs
	std::vector<std::reference_wrapper<watchdog_runnable>> m_runnables;

};

} // namespace dragent

