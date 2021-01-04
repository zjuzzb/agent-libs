#pragma once

#include "thread_safe_container/guarded_cache.h"
#include <functional>
#include <string>
#include <vector>

/**
 * Handle registration and parsing to for a Command Line 
 * Interface. The interface should be a list of nouns followed 
 * by a verb. So "verb" or "noun verb" or "noun noun verb". That 
 * is followed by a single dash to provide arguments. 
 *  
 * Example: 
 * prometheus target scrape -url http://abc:2020
 */
class command_line_manager
{

public:
	command_line_manager() {}

	/**
	 * Return a json response will all of the commands divided into 
	 * folders along with their description and long_description. 
	 * This is meant to be used by a command line client to provide 
	 * nicities like tab-complete. 
	 */
	std::string commands_json() const;

	enum class content_type
	{
		TEXT,
		JSON,
		YAML,
		ERROR
	};

	using response = std::pair<content_type, std::string>;
	/**
	 * Parse the given command, call the appropriate delegate and 
	 * return the response. 
	 * @return A string and the content_type of that string 
	 */
	response handle(const std::string& command) const;

	using argument_list = std::vector<std::pair<std::string, std::string>>;
	using cli_command = std::function<std::string(const argument_list& args)>;

	/**
	 * The structure which represents a command. Tbis must be 
	 * provided when a command is registered. 
	 */
	struct command_info
	{
		command_info() : type(content_type::TEXT) {}

		// If the handler is null, then this is a folder
		cli_command handler;
		std::string description;
		std::string long_description;
		content_type type;
	};

	/**
	 * Register a function to be called when the given command is 
	 * provided by the client. 
	 */
	void register_command(const std::string& command, const command_info &info);

	/**
	 * Provide a description for folder.
	 */
	void register_folder(const std::string &folder, const std::string &description);

	/**
	 * The instance of the command_line_manager.
	 */
	static command_line_manager& instance();

	/**
	 * Clear the registered commands
	 */
	void clear();

private:

	argument_list parse_arguments(const std::string& args, size_t offset) const;
	std::pair<command_line_manager::content_type, std::string> lookup_and_run_command(const std::string& command, const argument_list& args) const;


	using command_map = thread_safe_container::guarded_cache<std::string, command_info>;
	command_map m_commands;
};

