
#include "command_line_runnable.h"
#include <common_logger.h>
#include <type_config.h>
#include <chrono>

COMMON_LOGGER();

namespace
{

type_config<bool> c_enabled(true,
                            "Enable the command line.",
                            "command_line",
                            "enabled");

type_config<int> c_timeout(10000,
                           "The number of milliseconds to wait for a new message.",
                           "command_line",
                           "async_heartbeat_timeout_ms");
}

bool command_line_runnable::enabled()
{
	return c_enabled.get_value();
}

command_line_runnable::command_line_runnable(const is_terminated_delgate& terminated_delegate) : 
   watchdog_runnable("command_line", terminated_delegate)
{
}

void command_line_runnable::async_handle_command(const command_line_permissions &permissions,
						 const std::string &command, 
						 const async_callback& cb)
{
	std::unique_lock<std::mutex> guard(m_mtx);

	async_command cmd{permissions, command, cb};
	m_synchronized_queue.emplace_back(cmd);

	m_cv.notify_one();
}

void command_line_runnable::do_run()
{
	while (heartbeat()) 
	{
		process_commands();
	}
}

void command_line_runnable::process_commands()
{
	// Copy from the synchronized queue to the actual queue UNDER LOCK.
	// If the queue is empty then wait for a bit to see if a command
	// comes in.
	{
		std::unique_lock<std::mutex> guard(m_mtx);

		if (m_synchronized_queue.empty()) 
		{
			if (m_cv.wait_for(guard, std::chrono::milliseconds(c_timeout.get_value())) == std::cv_status::timeout)
			{
				return;
			}
		}

		for (auto &cmd : m_synchronized_queue)
		{
			m_queue.push_back(cmd);
		}
		m_synchronized_queue.clear();

	}

	// Process everything in the queue.
	for (auto& cmd : m_queue) 
	{
		auto response = command_line_manager::instance().handle(cmd.permissions, cmd.command);

		cmd.callback(response);

		heartbeat();
	}
	m_queue.clear();
}



