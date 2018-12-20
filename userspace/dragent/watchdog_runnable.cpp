
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
		LOG_ERROR("Attempted to set %s timeout after runnable started.",
			  m_name.c_str());
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

	DBG_LOG_ERROR("watchdog: %s, last activity %" PRId64
	              " ms ago, timeout %" PRIu64 " ms",
	              m_name.c_str(),
	              age_ms,
	              static_cast<uint64_t>(m_timeout_s * 1000ULL));

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
	LOG_INFO("%s starting", m_name.c_str());

	m_pthread_id = pthread_self();
	do_run();

	LOG_INFO("%s terminating", m_name.c_str());
}

uint64_t watchdog_runnable::monotonic_uptime_ms() const
{
	auto diff = std::chrono::steady_clock::now() - STEADY_START;
	return std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
}

} // namespace dragent
