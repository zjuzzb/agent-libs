#pragma once

#include <string>
#include <vector>

class sinsp_worker;

/**
 * Exposes an API to gracefully handle a set of signals that could cause the
 * agent to crash.
 */
namespace crash_handler
{
	/**
	 * Initialize the crash handler by registering signal handlers for
	 * the signals that the crash_handler can handle.
	 *
	 * @returns true if the initialization was successful, false otherwise.
	 */
	bool initialize();

	/**
	 * Returns a vector containing the signals that the crash_handler
	 * will handle.
	 */
	std::vector<int> get_crash_signals();

	/**
	 * Specify the log file to which the crash_handler will write crash
	 * information (e.g., stack trace).
	 *
	 * @param[in] crashdump_file the filename to which the crash_handler
	 *                           will write the crash dump.
	 */
	void set_crashdump_file(const std::string& crashdump_file);

	/**
	 * Returns the log file to which the crash_handler will write crash
	 * information.
	 */
	std::string get_crashdump_file();

	/**
	 * Specify the sinsp_worker that has an inspector, that has an analyzer,
	 * that can generate a memory report for the crash dump.
	 *
	 * @param[in] sinsp_worker the sinsp_worker from which the crash_handler
	 *                         can get a memory report.
	 */
	void set_sinsp_worker(const sinsp_worker* sinsp_worker);

	/**
	 * Returns the sinsp_worker that has an inspector, that has an analyzer,
	 * that can generate a memory report for the crash dump.
	 */
	const sinsp_worker* get_sinsp_worker();

	/**
	 * Write the given message to standard output.  If client code has
	 * previously specified the crashdump file, write the given message
	 * to that file as well.
	 *
	 * Note: This function is safe to use in the context of signal handlers.
	 *
	 * Preconditions: This function expects that set_crashdump_file()
	 *                has been called with a valid filename.
	 *
	 * @param[in] message The message that the crash_handler will write
	 */
	void log_crashdump_message(const char* message);
}
