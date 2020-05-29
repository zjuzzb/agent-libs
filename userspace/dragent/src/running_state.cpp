#include "running_state.h"
#include "common_logger.h"
#include "exit_code.h"

COMMON_LOGGER();

namespace dragent
{

running_state running_state::m_instance;

running_state::running_state() :
	m_terminated(false),
	m_exit_code(exit_code::SHUT_DOWN)
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

void running_state::terminate(uint8_t exit_code, const char * msg)
{
	if (m_terminated) {
		if (exit_code != m_exit_code) {
			LOG_DEBUG("Ignoring additional call to terminate. Only "
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
}

uint8_t running_state::exit_code() const
{
	return m_exit_code;
}

void running_state::reset_for_test()
{
	m_exit_code = exit_code::SHUT_DOWN;
	m_terminated = false;
}

}
