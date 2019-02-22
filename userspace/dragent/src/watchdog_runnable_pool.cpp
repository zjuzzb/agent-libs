
#include "watchdog_runnable_pool.h"
#include "logger.h"

DRAGENT_LOGGER();

namespace dragent
{

void watchdog_runnable_pool::start(watchdog_runnable& toStart, uint64_t timeout_s)
{
	toStart.timeout_ms(timeout_s * 1000);
	Poco::ThreadPool::defaultPool().start(toStart, toStart.name());
	m_runnables.push_back(toStart);
}

watchdog_runnable_pool::unhealthy_runnables watchdog_runnable_pool::unhealthy_list() const
{
	unhealthy_runnables unhealthy;

	// Call into every watchdog_runnable and check whether it is healthy
	for(auto current : m_runnables)
	{
		int64_t age_ms;
		watchdog_runnable::health health = current.get().is_healthy(age_ms);
		if(health != watchdog_runnable::health::HEALTHY)
		{
			unhealthy.emplace_back(unhealthy_runnable{ current.get(), health, age_ms });
		}
	}

	return unhealthy;
}

void watchdog_runnable_pool::stop_all()
{
	Poco::ThreadPool::defaultPool().stopAll();
}

void watchdog_runnable_pool::log_report() const
{
	for(auto current : m_runnables)
	{
		current.get().log_report();
	}
}


} // namespace dragent
