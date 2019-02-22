#pragma once

#include <atomic>
#include <Poco/Thread.h>


namespace dragent 
{

/**
 * Implements the POCO Runnable class and provides a simple
 * interface for a watchdog process to check if the class
 * runnable is still alive.
 */
class watchdog_runnable : public Poco::Runnable
{
public:
	static const uint64_t NO_TIMEOUT = 0;

	watchdog_runnable(const std::string& name);

	/**
	 * @return whether this runnable has ever called heartbeat
	 */
	bool is_started() const
	{
		return m_last_heartbeat_ms;
	}

	/**
	 * @return the name of the runnable
	 */
	const std::string& name() const
	{
		return m_name;
	}

	/**
	 * @return the id of the thread (returning a copy because this
	 *         is stored as an atomic)
	 */
	pthread_t pthread_id() const
	{
		return m_pthread_id;
	}

	enum class health
	{
		HEALTHY = 0,
		TIMEOUT,
		FATAL_ERROR
	};
	/**
	 * @param age_ms the number of milliseconds that has elapsed
	 *      	 since the previous heartbeat
	 *
	 * @return health the health of the runnable
	 */
	health is_healthy(int64_t& age_ms) const;

	/**
	 * @return whether enough time has passed since the given
	 *         last_heartbeat for the runnable to have timed out
	 */
	static bool is_timed_out(const std::string& name,
				 uint64_t last_heartbeat,
				 uint64_t timeout_ms,
				 int64_t& age_ms);

	/**
	 * Set the timeout. This is not set in construction because the
	 * configuration is loaded after the runnables are constructed.
	 * This must be called before the runnable is started or the value
	 * will be ignored.
	 */
	void timeout_ms(uint64_t value_ms);

	/**
	 * @return the watchdog timeout
	 */
	uint64_t timeout_ms() const
	{
		return m_timeout_ms;
	}

	/**
	 * Log how long since the last heartbeat.
	 */
	void log_report();

	/**
	 * Must be implemented by the derived class and must do whatever
	 * the runnable does. Must call heartbeat or the dragent will
	 * restart.
	 */
	virtual void do_run() = 0;

protected:
	/**
	 * Marks this runnable as alive so that the is_healthy check will
	 * return true. Should be called by the do_run function in the
	 * derived class.
	 * @return whether to continue
	 */
	bool heartbeat();

private:

	void run() override;

	std::atomic<bool> m_terminated;
	std::atomic<uint64_t> m_last_heartbeat_ms;
	std::atomic<pthread_t> m_pthread_id;

	// This timeout is not const, but it can only be set before runnable is
	// started so it does not need to be atomic.
	uint32_t m_timeout_ms;
	const std::string m_name;
};

} // namespace dragent

