#pragma once

#include "command_line_manager.h"
#include "async_command_handler.h"
#include <watchdog_runnable.h>
#include <condition_variable>
#include <mutex>

/**
 * Runnable to asynchronously run commands. This will sit idle 
 * until a command is received. Then it will run the commmand 
 * and call the appropriate callback. 
 */
class command_line_runnable : public watchdog_runnable,
                              public async_command_handler
{

public:
	/**
	 * Return whether the command line is enabled.
	 */
	static bool enabled();

	command_line_runnable(const is_terminated_delgate& terminated_delegate);

	/**
	 * Pass the command to the this runnable to run asynchronously 
	 * and then run the callback. 
	 */
	void async_handle_command(const std::string &command, const async_callback& cb) override;

private:
	/**
	 * Must be implemented by the derived class and must do whatever
	 * the runnable does. Must call heartbeat or the dragent will
	 * restart.
	 */
	void do_run() override;

	void process_commands();

	std::mutex m_mtx;
	std::condition_variable m_cv;

	struct async_command
	{
		std::string command;
		async_callback callback;
	};
	std::vector<async_command> m_synchronized_queue;
	std::vector<async_command> m_queue;
};

