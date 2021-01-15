#pragma once

#include "command_line_permission.h"
#include <vector>

/**
 * A vector of permissions with helper functions.
 */
class command_line_permissions : public std::vector<command_line_permission>
{
public:
	command_line_permissions() 
	{}

	command_line_permissions(std::initializer_list<command_line_permission> il) :
	  std::vector<command_line_permission>(il)
	{}

	/**
	 * Convert the permissions to a string. If there is more than 
	 * one permission then it they will be seperated by a |.
	 */
	std::string to_string() const;

	/**
	 * Return whether the given set of permissions is a subset of 
	 * this set of permissions. 
	 */
	bool is_accessable(const command_line_permissions& client_permissions) const;

};
