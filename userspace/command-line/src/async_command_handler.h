#pragma once

#include "command_line_manager.h"
#include <functional>

/** 
 * Pure virtual that can asynchronously handle a command-line 
 * command (Interface Segregation Principle). 
 */
class async_command_handler
{
public:
	using async_callback = std::function<void(const command_line_manager::response&)>;

	/**
	 * Run the given command asynchronously and then call the given 
	 * callback. 
	 */
	virtual void async_handle_command(const command_line_permissions &permissions, 
                                          const std::string &command, 
	                                  const async_callback& cb) = 0;
};
