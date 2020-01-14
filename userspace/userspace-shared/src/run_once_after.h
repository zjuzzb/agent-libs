/**
 * @file
 *
 * Interface to run_once_after.
 *
 * @copyright Copyright (c) 2020 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdint>
#include <functional>

namespace userspace_shared
{

/**
 * Runs the given function once after the given number of nanoseconds from
 * the point at which the object was created.
 */
class run_once_after
{
public:
	using clocksource = std::function<uint64_t()>;
	using target_fn = std::function<void()>;

	/**
	 * Initializes this run_once_after.
	 *
	 * @param[in] timeout_ns The amount of time, in nanoseconds,
	 *                       after creation, as determined by the given
	 *                       clock, after which run() will run the given
	 *                       function.
	 * @param[in] clock      The source of time in nanoseconds
	 *                       (e.g., sinsp_utils::get_current_time_ns).
	 *                       Note that this is the function, not the
	 *                       return value of the function.
	 */
	explicit run_once_after(uint64_t timeout_ns, clocksource clock);

	/**
	 * Updates the timeout is nanoseconds provided to the constructor.
	 * This is useful if the timeout isn't known at construction time.
	 *
	 * Note that if run() has invoked the given function before this
	 * is called, it will not re-run the function, even if the given
	 * timeout_ns value would schedule it later).
	 *
	 * @param[in] timeout_ns The amount of time, in nanoseconds,
	 *                       after creation, as determined by the given
	 *                       clock, after which run() will run the given
	 *                       function.
	 */
	void set_timeout(uint64_t timeout_ns);

	/**
	 * Returns the current timeout value, in nanoseconds.
	 */
	uint64_t get_timeout() const;

	/**
	 * Returns the time, in nanoseconds, after which a call to run() might
	 * invoke the given function.  This is (creation_time + timeout).
	 */
	uint64_t get_time_to_run() const;

	/**
	 * Each call to run potentially executes the given fn if:
	 * (1) the current time is greater than or equal to the creation
	 *     time + the timeout and
	 * (2) a previous call to run() hasn't already executed a function.
	 *
	 * If neither of those two conditions holds, then this method returns
	 * immediately.  The client is responsible for periodically calling
	 * this method; there is no threading involved here.
	 *
	 * @param[in] fn The function to invoke
	 */
	void run(target_fn fn);

private:
	/** The time at which this run_once_after object was created. */
	const uint64_t m_creation_time;

	/** The time since m_creation_time after which run can run the fn. */
	uint64_t m_timeout;

	/** A function that returns the current time, in nanoseconds. */
	clocksource m_time_in_ns_function;

	/** Has run() run the function already? */
	bool m_executed;
};

} // namespace userspace_shared
