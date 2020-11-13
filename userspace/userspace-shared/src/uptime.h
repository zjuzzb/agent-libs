#pragma once

/**
 * Monotonic time that the application has been running
 */
namespace uptime
{
	/**
	 * @return application uptime in milliseconds
	 */
	uint64_t milliseconds();

	/**
	 * @return application uptime in seconds
	 */
	uint64_t seconds();

} // namespace uptime

