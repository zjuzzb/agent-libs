#pragma once
#include <string>

/**
 * The different permissions that can be assigned to commands. 
 * These permissions are associated with roles on the backend so 
 * so that the user has access to the correct set of commands. 
 */
enum command_line_permission
{
	CLI_AGENT_STATUS,
	CLI_AGENT_INTERNAL_DIAGNOSTICS,
	CLI_NETWORK_CALLS_TO_REMOTE_PODS,
	CLI_VIEW_CONFIGURATION,
	CLI_VIEW_SENSITIVE_CONFIGURATION
};

/**
 * Convert from permission to string.
 */
std::string command_line_permission_to_string(command_line_permission perm);
