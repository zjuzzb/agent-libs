
#include "watchdog_runnable_pool.h"
#include "logger.h"

DRAGENT_LOGGER();

namespace dragent
{

void watchdog_runnable_pool::start(watchdog_runnable& toStart, uint64_t timeout_s)
{
	toStart.timeout(timeout_s);
	Poco::ThreadPool::defaultPool().start(toStart, toStart.name());
	m_runnables.push_back(toStart);
}

watchdog_runnable_pool::hung_runnables watchdog_runnable_pool::unhealthy_runnables() const
{
	hung_runnables unhealthy;

	// Call into every watchdog_runnable and check whether it is healthy
	for(auto current : m_runnables)
	{
		int64_t age_ms;
		if(!current.get().is_healthy(age_ms))
		{
			unhealthy.emplace_back(hung_runnable{current.get(), age_ms });
		}
	}

	return unhealthy;
}

void watchdog_runnable_pool::stop_all()
{
	Poco::ThreadPool::defaultPool().stopAll();
}

} // namespace dragent
