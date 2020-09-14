#pragma once

#include <cstdint>
#include <string>

/**
 * @brief Manage CPU profiles (configuration, rotation)
 *
 * Whenever `dragent_cpu_profile_enabled` is enabled in the config file,
 * each instance of this class will ensure the CPU profile is generated
 * and stored according to the configured interval and number of profile files.
 *
 * You need to call .tick() periodically for the profiles to be rotated.
 * The final profile is flushed when the `cpu_profiler` object is destroyed,
 * but this only happens on process shutdown when the process shuts down cleanly
 * (destructors aren't called on receiving a signal, obviously)
 *
 * Note: only a single instance of this class should exist in a particular
 * process
 */
class cpu_profiler
{
public:
	/**
	 * @brief Initialize a cpu_profiler
	 * @param filename_pattern Path of the profile; will have the sequence
	 *        number appended
	 */
	explicit cpu_profiler(const std::string&& filename_pattern);

	/**
	 * @brief Check if the profile needs to be started or rotated
	 *
	 * Call this periodically (no need to go faster than e.g. 1/sec)
	 */
	void tick();

	virtual ~cpu_profiler();

private:

	void start();

	const std::string m_filename_pattern;

	bool m_trace_enabled;
	uint32_t m_trace_id;
	uint64_t m_last_rotated;
};
