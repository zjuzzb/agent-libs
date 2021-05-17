#include "common_logger.h"
#include "exit_code.h"
#include "running_state.h"
#include "signal.h"
#include "type_config.h"

#include <iostream>
#include <thread>

COMMON_LOGGER();

namespace
{
type_config<uint64_t> c_shutdown_deadman_s(
    30,
    "How long to wait for graceful shutdown before sigkilling ourselves",
    "shutdown_deadman");

}

namespace dragent
{
running_state running_state::m_instance;

void running_state::run_shutdown_deadman(pthread_t tid)
{
	for (uint64_t loops = 0; loops < c_shutdown_deadman_s.get_value(); loops++)
	{
		if (loops % 5 == 0)
		{
			LOG_INFO("Waited %ld seconds for graceful shutdown to complete", loops);
		}
		else
		{
			LOG_DEBUG("Waited %ld seconds for graceful shutdown to complete", loops);
		}
		sleep(1);
	}
	LOG_FATAL("Process did not terminate after %ld seconds. Forcefully terminating.",
	          c_shutdown_deadman_s.get_value());
	pthread_kill(tid, SIGABRT);
	sleep(5);  // Allows the thread a chance to print a stack trace
	kill(getpid(), SIGKILL);
	LOG_ERROR("Something went wrong.");
}

running_state::running_state()
    : m_terminated(false),
      m_exit_code(exit_code::SHUT_DOWN),
      m_deadman_enabled(true)
{
}

void running_state::restart()
{
	terminate(exit_code::RESTART, "Restarting dragent process gracefully.");
}

void running_state::restart_for_config_update()
{
	terminate(exit_code::CONFIG_UPDATE,
	          "Restarting dragent process gracefully because a configuration "
	          "update was received.");
}

void running_state::shut_down()
{
	terminate(exit_code::SHUT_DOWN, "Shutting down dragent process gracefully.");
}

bool running_state::is_terminated() const
{
	return m_terminated;
}

void running_state::terminate(uint8_t exit_code, const char* msg)
{
	if (m_terminated)
	{
		if (exit_code != m_exit_code)
		{
			LOG_DEBUG(
			    "Ignoring additional call to terminate. Only "
			    "the first call is obeyed. Ignoring \"%s\"",
			    msg);
		}
		return;
	}

	LOG_INFO(msg);

	m_exit_code = exit_code;
	// These are locked seperately so set m_terminated last since
	// that is what is expected to get checked first
	m_terminated = true;

	// In case we hang somewhere
	if (m_deadman_enabled)
	{
		std::thread deadman(run_shutdown_deadman, m_main_thread_tid);
		deadman.detach();
	}
}

uint8_t running_state::exit_code() const
{
	return m_exit_code;
}

void running_state::reset_for_test()
{
	m_exit_code = exit_code::SHUT_DOWN;
	m_terminated = false;
	m_deadman_enabled = false;
}

void running_state::register_main_thread_tid(pthread_t tid)
{
	m_main_thread_tid = tid;
}

}  // namespace dragent
