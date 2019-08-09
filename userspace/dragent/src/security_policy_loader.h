/**
 * @file
 *
 * Interface to security_policy_loader.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace draiosproto {
class policies;
}

namespace dragent
{

/**
 * Interface to objects that can load security policies.
 */
class security_policy_loader
{
public:
	virtual ~security_policy_loader() = default;

	virtual bool load_policies(const draiosproto::policies& policies,
	                           std::string& errstr) = 0;
};

} // namespace dragent
