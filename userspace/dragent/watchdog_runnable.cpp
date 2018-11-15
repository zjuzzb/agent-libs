
#include "watchdog_runnable.h"
#include "configuration.h"
#include "logger.h"

DRAGENT_LOGGER();

namespace {

const std::chrono::time_point<std::chrono::steady_clock> STEADY_START = std::chrono::steady_clock::now();

} // anonymous namespace

namespace dragent
{

watchdog_runnable::watchdog_runnable(const std::string& name) :
	// Purposely initializing heartbeat to 0 so that we can check
	// whether runnable has ever started.
	m_last_heartbeat_ms(0),
	m_pthread_id(0),
	m_timeout_s(0),
	m_name(name)
{
}


void watchdog_runnable::timeout(uint64_t value)
{
	if(is_started())
	{
		LOG_ERROR("Attempted to set" + m_name +  " timeout after runnable started.");
		return;
	}

	m_timeout_s = value;
}


bool watchdog_runnable::heartbeat()
{
	if(dragent_configuration::m_terminate)
	{
		return false;
	}

	m_last_heartbeat_ms = monotonic_uptime_ms();
	return true;
}

bool watchdog_runnable::is_healthy(int64_t& age_ms) const
{
	// This might look odd, but until the heartbeat occurs the first time
	// we always consider the watchdog_runnable to be healthy. This is kept to be
	// consistent with previous implementation.
	if(!m_last_heartbeat_ms)
	{
		return true;
	}

	age_ms = monotonic_uptime_ms() - m_last_heartbeat_ms;

#if _DEBUG
	LOG_DEBUG("watchdog: " +  m_name + " , last activity " + NumberFormatter::format(age_ms) + " ms ago, timeout " +  NumberFormatter::format(m_timeout_s * 1000) + " ms");
#endif

	if(m_timeout_s == NO_TIMEOUT)
	{
		return true;
	}

	if(age_ms <= static_cast<int64_t>(m_timeout_s * 1000LL))
	{
		return true;
	}

	// Found an unhealthy watchdog_runnable
	return false;
}

void watchdog_runnable::run()
{
	LOG_INFO(m_name + " starting");

	m_pthread_id = pthread_self();
	do_run();

	LOG_INFO(m_name + " terminating");
}

uint64_t watchdog_runnable::monotonic_uptime_ms() const
{
	auto diff = std::chrono::steady_clock::now() - STEADY_START;
	return std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
}

} // namespace dragent
