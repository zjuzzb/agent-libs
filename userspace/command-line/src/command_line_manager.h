#pragma once

#include "command_line_permissions.h"
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
	 * Return a json response with all of the commands divided into 
	 * folders along with their description and long_description. 
	 * This is meant to be used by a command line client to provide 
	 * nicities like tab-complete. 
	 */
	std::string commands_json(const command_line_permissions &user_permissions) const;

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
	response handle(const command_line_permissions &user_permissions, const std::string& command) const;

	using argument_list = std::vector<std::pair<std::string, std::string>>;
	using cli_command = std::function<std::string(const argument_list& args)>;

	/**
	 * The structure which represents a command. Tbis must be 
	 * provided when a command is registered. 
	 */
	struct command_info
	{
		command_info() : 
		  type(content_type::TEXT)
		{}

		/**
		 * The permissions that the client mush have to access this 
		 * command. Every command_info must give at least one permission
		 * or the command will not be visible. This is purposely not 
		 * given a default because we want developers to always be 
		 * explicit about what permissions a command needs. 
		 */
		command_line_permissions permissions;
		/** 
		 *  The handler to call when the operator executes the command.
		 *  If the handler is null, then this is a folder.
		 */
		cli_command handler;
		/**
		 * The short description. This is shown when viewing help for a 
		 * folder. 
		 */
		std::string short_description;
		/**
		 * The long description with examples on how the command is 
		 * used. This is shown when viewing help on the command itself. 
		 */
		std::string long_description;
		/**
		 * The content type returned by this command. This allows the UI 
		 * to display it appropriately. 
		 */
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

	response handle_registered_command(const command_line_permissions &user_permissions, const std::string &command) const;


	argument_list parse_arguments(const std::string &args, size_t offset) const;
	std::pair<command_line_manager::content_type, std::string> lookup_and_run_command(const command_line_permissions &user_permissions, const std::string& command, const argument_list& args) const;


	using command_map = thread_safe_container::guarded_cache<std::string, command_info>;
	command_map m_commands;
};

