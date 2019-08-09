/**
 * @file
 *
 * Interface to security_baselines_loader.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace draiosproto {
class baselines;
}

namespace dragent
{

/**
 * Interface to objects that can load security baselines.
 */
class security_baselines_loader
{
public:
	virtual ~security_baselines_loader() = default;

	virtual bool load_baselines(const draiosproto::baselines& baselines,
	                            std::string& errstr) = 0;
};

} // namespace dragent
