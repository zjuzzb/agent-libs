#ifndef CYGWING_AGENT
#define __STDC_FORMAT_MACROS

#include <cinttypes>
#include "common_logger.h"
#include "our_k8s_limits.h"
#include <unistd.h>
#include <sys/sysinfo.h>

COMMON_LOGGER();

using namespace std;

our_k8s_limits::our_k8s_limits(uint64_t info_interval,
                               uint64_t warning_interval,
                               uint32_t requests_threshold_pct,
                               uint32_t limits_threshold_pct):
	m_k8s_limits_logging_info_interval(info_interval * ONE_SECOND_IN_NS),
	m_k8s_limits_logging_warning_interval(warning_interval * ONE_SECOND_IN_NS),

	m_requests_threshold_pct(requests_threshold_pct),
	m_limits_threshold_pct(limits_threshold_pct),
	m_requests_cpu_cores(0),
	m_limits_cpu_cores(0),
	m_requests_mem_bytes(0),
	m_limits_mem_bytes(0),
	m_imported(false)
{
	// Get total data from the system
	struct sysinfo info;
	auto error = sysinfo(&info);
	if (error == 0)
	{
		m_total_mem_bytes = info.totalram * info.mem_unit;
	}
	else
	{
		LOG_WARNING("Cannot get system total memory");
		m_total_mem_bytes  = 0;
	}
	// We presumptuosly assume the number of online processors is not bound to change while we're running
	m_total_cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);

}

void our_k8s_limits::import_k8s_limits(const draiosproto::k8s_container_status_details &our_container)
{
	// Get requests/limits from k8s_container_status_details
	if (our_container.has_requests_cpu_cores())
	{
		m_requests_cpu_cores = our_container.requests_cpu_cores();
	}
	if (our_container.has_requests_mem_bytes())
	{
		m_requests_mem_bytes = our_container.requests_mem_bytes();
	}
	if (our_container.has_limits_cpu_cores())
	{
		m_limits_cpu_cores = our_container.limits_cpu_cores();
	}
	if (our_container.has_limits_mem_bytes())
	{
		m_limits_mem_bytes = our_container.limits_mem_bytes();
	}
	m_imported = true;
}

bool our_k8s_limits::log_warnings() const
{
	bool warn_emitted = false;

	if (((m_requests_cpu_cores != 0) && (m_requests_cpu_cores * 100 / m_total_cpu_cores < m_requests_threshold_pct))
	|| ((m_requests_mem_bytes != 0) && (m_requests_mem_bytes * 100 / m_total_mem_bytes < m_requests_threshold_pct)))
	{
		LOG_WARNING("requests should be at least %u%% of the total available resources --"
					"the agent may face resource starvation issues and may not operate with full fidelity",
					m_requests_threshold_pct);
		warn_emitted = true;
	}
	if (((m_limits_cpu_cores != 0) && (m_limits_cpu_cores * 100 / m_total_cpu_cores < m_limits_threshold_pct))
	|| ((m_limits_mem_bytes != 0) && (m_limits_mem_bytes * 100 / m_total_mem_bytes < m_limits_threshold_pct)))
	{
		LOG_WARNING("limits should be at least %u%% of the total available resources --"
					"the agent may face resource starvation issues while handling spikes in load.",
					m_limits_threshold_pct);
		warn_emitted = true;
	}
	return warn_emitted;
}

void our_k8s_limits::log_info() const
{
	LOG_INFO("requests.cpu_cores: %f", m_requests_cpu_cores);
	LOG_INFO("  limits.cpu_cores: %f",   m_limits_cpu_cores);
	LOG_INFO("   total.cpu_cores: %f",    m_total_cpu_cores);
	LOG_INFO("requests.mem_bytes: %ld", m_requests_mem_bytes);
	LOG_INFO("  limits.mem_bytes: %ld",   m_limits_mem_bytes);
	LOG_INFO("   total.mem_bytes: %ld",    m_total_mem_bytes);
}

void our_k8s_limits::periodically_log_our_k8s_limits(uint64_t ts)
{
	m_k8s_limits_logging_info_interval.run([this]() {
		log_info();
	}, ts);

	m_k8s_limits_logging_warning_interval.run([this]() {
		if(log_warnings()) {
			log_info();;
		}
	}, ts);
}

#endif  // CYGWING_AGENT
