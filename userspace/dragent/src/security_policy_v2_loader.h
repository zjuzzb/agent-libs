/**
 * @file
 *
 * Interface to security_policy_v2_loader.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace draiosproto {
class policies_v2;
}

namespace dragent
{

/**
 * Interface to objects that can load security v2 policies.
 */
class security_policy_v2_loader
{
public:
	virtual ~security_policy_v2_loader() = default;

	virtual bool load_policies_v2(const draiosproto::policies_v2& policies,
	                              std::string& errstr) = 0;
};

} // namespace dragent
