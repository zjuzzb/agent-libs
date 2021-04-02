
#include "command_line_permissions.h"

/**
 * Helpers to create commands for the agent cli.
 */
namespace configuration_cli
{

/**
 * Add a command for the given configuration file.
 */
void add(const std::string &title, 
	 const std::string &file,
	 const command_line_permissions& perms);


/**
 * Remove the sensitive configuration from the given string and 
 * return the resultant string. 
 * This is exposed for the unit test. 
 */
std::string remove_sensitive_configuration(const std::string &json);

}
