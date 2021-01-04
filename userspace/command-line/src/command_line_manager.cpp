
#include "command_line_manager.h"
#include "command_line_error.h"
#include "common_logger.h"
#include "string_utils.h"
#include <json/json.h>
#include <stdexcept>

COMMON_LOGGER();

std::string command_line_manager::commands_json() const
{
	Json::Value root;
	auto &commands = root["commands"];

	m_commands.visit([&commands](const command_map::element_pair& cmd) 
	{
		size_t delimiter_pos;
		std::string right = cmd.first;
		auto *current = &commands;

		// Iterate through the commands to get to the right folder
		while ((delimiter_pos = right.find(' ')) != std::string::npos) 
		{
			std::string left = right.substr(0, delimiter_pos);
			right = right.substr(delimiter_pos+1);
			current = &(*current)[left]["subs"];

		}

		// Add the description for this element
		current = &(*current)[right];

		if (!cmd.second.description.empty())
		{
			(*current)["description"] = cmd.second.description;
		}
		if (!cmd.second.long_description.empty())
		{
			(*current)["long_description"] = cmd.second.long_description;
		}

	});

	return root.toStyledString();
}

std::pair<command_line_manager::content_type, std::string> command_line_manager::handle(const std::string& command) const
{
	try
	{
		// if we have args then it will always start with a space and a dash 
		auto found = command.find(" -");

		if (found == std::string::npos) 
		{
			std::string command_copy = command;
			string_utils::trim(command_copy);
			return lookup_and_run_command(command_copy, argument_list());
		}
		std::string left = command.substr(0, found);
		std::string right = command.substr(found);
		auto args = parse_arguments(right, left.size());
		string_utils::trim(left);
		return lookup_and_run_command(left, args);
		
	}
	catch (command_line_error &ex)
	{
		auto err = std::string("Error: ") + ex.what();
		return std::make_pair(command_line_manager::content_type::ERROR, err);
	}	
}

void command_line_manager::register_command(const std::string &command, 
					    const command_info &info)
{
	m_commands.insert(command, info);
}

void command_line_manager::register_folder(const std::string &folder,
					   const std::string &description)
{
	command_info info;
	info.description = description;
	m_commands.insert(folder, info);
}

command_line_manager& command_line_manager::instance()
{
	static std::unique_ptr<command_line_manager> s_instance = std::unique_ptr<command_line_manager>(new command_line_manager());

	return *s_instance;
}

command_line_manager::argument_list command_line_manager::parse_arguments(const std::string& args, size_t offset) const
{
	/** 
	 * Ok: 
	 * -on -color red 
	 * -item steak   -done-ness "medium well" 
	 * -on -color red 
	 *  
	 * Bad: 
	 * - color red blue
	 * - -
	 *  
	 * See unit test for more examples 
	 */

	argument_list arg_list;

	auto it = args.cbegin();
	while (it != args.cend()) 
	{
		// Skip spaces
		if (*it == ' ') 
		{
			++it;
			continue;
		}

		// Starting a new argument name
		if (*it != '-') 
		{
			THROW_CLI_ERROR("Expected dash in argument list at position %zu.", 
			                offset + std::distance(args.begin(), it));
		}
		// Skip the dash
		++it;

		if (it == args.cend()) 
		{
			THROW_CLI_ERROR("Argument list should not end with a dash.");
		}
		if (*it == ' ') 
		{
			THROW_CLI_ERROR("There should not be a space between the dash and argument name at position %zu.", 
			                offset + std::distance(args.begin(), it));
		}
		if (*it == '-') 
		{
			THROW_CLI_ERROR("There should not be a double dash at position %zu.", 
			                offset + std::distance(args.begin(), it));
		}

		// Find the end of this argument name which always ends with a space
		// or the end of the buffer
		std::string argument_name;
		argument_name.reserve(20);
		while (it != args.cend() && *it != ' ') 
		{
			argument_name += *it;
			++it;
		}

		// Skip additional spaces
		while (it != args.cend() && *it == ' ') 
		{
			++it;
		}

		// If this is the end then save the arg name
		if(it == args.cend())
		{
			arg_list.push_back(std::make_pair(argument_name, std::string()));
			break;
		}

		// If this is a new argument then save and start over
		if (*it == '-') 
		{
			arg_list.push_back(std::make_pair(argument_name, std::string()));
			continue;
		}

		// The remaining section is the argument value. First check
		// whether it is surrounded by quotes
		if (*it == '"' || *it == '\'') 
		{
			THROW_CLI_ERROR("Quotes aren't supported in argument values at position %zu.", 
			                offset + std::distance(args.begin(), it));
		}

		// Find the end of this argument value which always ends with a space
		// or the end of the buffer
		std::string argument_value;
		argument_value.reserve(100);
		while (it != args.cend() && *it != ' ') 
		{
			argument_value += *it;
			++it;
		}

		// Skip additional spaces
		while (it != args.cend() && *it == ' ') 
		{
			++it;
		}
		 
		arg_list.push_back(std::make_pair(argument_name, argument_value));
	}

	return arg_list;
}

std::pair<command_line_manager::content_type, std::string> command_line_manager::lookup_and_run_command(const std::string& command, const argument_list& args) const
{
	auto handle = m_commands.read_handle(command);

	if (!handle.valid()) {
		THROW_CLI_ERROR("Unrecognized command.");
	}

	if (!handle->handler) 
	{
		// This is a folder. Just return the description.
		auto desc = handle->long_description.empty() ?
			handle->description : handle->long_description;
		return std::make_pair(command_line_manager::content_type::TEXT, desc);

	}

	auto str = handle->handler(args);
	return std::pair<command_line_manager::content_type, std::string>(handle->type, str); 
}

void command_line_manager::clear()
{
	m_commands.clear();
}

// generate template functions
#include "thread_safe_container/guarded_cache.hpp"
template class thread_safe_container::guarded_cache<std::string, command_line_manager::command_info>;
