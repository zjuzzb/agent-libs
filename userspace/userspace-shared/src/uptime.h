#pragma once

/**
 * Monotonic time that the application has been running
 */
namespace uptime
{
	/**
	 * @return application uptime in ms
	 */
	uint64_t milliseconds();

} // namespace uptime

