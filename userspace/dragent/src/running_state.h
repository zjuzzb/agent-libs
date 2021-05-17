#pragma once

#include <atomic>
#include <unistd.h>
#include <pthread.h>

namespace dragent {

/**
 * Manages the running state of the dragent process and all of 
 * its subprocesses. This is tightly coupled to the monitor 
 * class which restarts the agent when needed. This class is 
 * thread-safe but access is not guarded; instead, all members 
 * are expected to be atomic. 
 */
class running_state {

public:
	static running_state &instance()
	{
		return m_instance;
	}

	/**
	 * Return whether the application is being restarted or shut 
	 * down. 
	 */
	bool is_terminated() const;

	/**
	 * Restart the dragent process and all of its subprocesses. 
	 */
	void restart();

	/**
	 * Restart for a configuration update.
	 */
	void restart_for_config_update();

	/**
	 * Shut down the dragent process and all of its subprocesses. 
	 */
	void shut_down();

	/**
	 * Return the appropriate exit code for the application.
	 */
	uint8_t exit_code() const;

	/**
	 * Used in testing to reset the instance.
	 */
	void reset_for_test();

	/**
	 * used to register the tid of the "main" thread of the process, or one
	 * to which we should send thread-specific signals, if necessary. Should
	 * only ever be called once, around startup time
	 */
	void register_main_thread_tid(pthread_t tid);

private:

	running_state();
	void terminate(uint8_t exit_code, const char * msg);
	static void run_shutdown_deadman(pthread_t main_thread_tid);

	static running_state m_instance;

	std::atomic<bool> m_terminated;
	std::atomic<uint8_t> m_exit_code;

	bool m_deadman_enabled;
	pthread_t m_main_thread_tid;

	// Deleted to prevent accidental usage
	running_state(const running_state&) = delete;
	running_state& operator=(const running_state&) = delete;
};

}


