#pragma once

#include <atomic>
#include <chrono>
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

	/**
	 * @param age_ms the number of milliseconds that has elapsed
	 *      	 since the previous heartbeat
	 *
	 * @return bool whether the runnable has called heartbeat within
	 *         the timeout
	 */
	bool is_healthy(int64_t& age_ms) const;

	/**
	 * Set the timeout. This is not set in construction because the
	 * configuration is loaded after the runnables are constructed.
	 * This must be called before the runnable is started or the value
	 * will be ignored.
	 */
	void timeout(uint64_t value);

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
	 * @return bool whether to continue
	 */
	bool heartbeat();

private:
	uint64_t monotonic_uptime_ms() const;

	void run() override;

	std::atomic<uint64_t> m_last_heartbeat_ms;
	std::atomic<pthread_t> m_pthread_id;

	// This timeout is not const, but it can only be set before runnable is
	// started so it does not need to be atomic.
	uint64_t m_timeout_s;
	const std::string m_name;
};

} // namespace dragent

