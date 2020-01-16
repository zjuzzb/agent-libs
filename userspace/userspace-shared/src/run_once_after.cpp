/**
 * @file
 *
 * Implementation of run_once_after.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#include "run_once_after.h"

namespace userspace_shared
{

run_once_after::run_once_after(const uint64_t timeout_ns,
                               clocksource clock):
	m_creation_time(clock()),
	m_timeout(timeout_ns),
	m_time_in_ns_function(clock),
	m_executed(false)
{ }

void run_once_after::set_timeout(const uint64_t timeout_ns)
{
	m_timeout = timeout_ns;
}

uint64_t run_once_after::get_timeout() const
{
	return m_timeout;
}

uint64_t run_once_after::get_time_to_run() const
{
	return m_creation_time + m_timeout;
}

void run_once_after::run(target_fn fn)
{
	if (!m_executed && (m_time_in_ns_function() >= get_time_to_run()))
	{
		m_executed = true;
		fn();
	}
}

} // namespace userspace_shared
