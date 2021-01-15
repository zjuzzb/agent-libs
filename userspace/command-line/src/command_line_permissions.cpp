#include "command_line_permissions.h"

std::string command_line_permissions::to_string() const
{
	std::string result;

	for (auto policy : *this) 
	{
		if (!result.empty()) 
		{
			result += "|";
		}
		result += command_line_permission_to_string(policy);
	}

	return result;
}

bool command_line_permissions::is_accessable(const command_line_permissions& client_permissions) const
{
	for (auto required_permission : *this) 
	{
		bool found = false;
		for (auto client_permission : client_permissions) 
		{
			if (required_permission == client_permission) 
			{
				found = true;
			}
		}

		if (!found) 
		{
			return false;
		}
	}

	return true;
}
