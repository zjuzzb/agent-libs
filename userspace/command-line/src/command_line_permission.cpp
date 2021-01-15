#include "command_line_permission.h"

std::string command_line_permission_to_string(command_line_permission perm)
{
	switch (perm) 
	{
	case CLI_AGENT_STATUS : return "AGENT_STATUS";
	case CLI_AGENT_INTERNAL_DIAGNOSTICS : return "AGENT_INTERNAL_DIAGNOSTICS";
	case CLI_NETWORK_CALLS_TO_REMOTE_PODS : return "NETWORK_CALLS_TO_REMOTE_PODS";
	case CLI_VIEW_CONFIGURATION : return "VIEW_CONFIGURATION";
	case CLI_VIEW_SENSITIVE_CONFIGURATION : return "VIEW_SENSITIVE_CONFIGURATION";
	}

	return "UNKNOWN";
}
