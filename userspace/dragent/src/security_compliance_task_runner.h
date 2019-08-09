/**
 * @file
 *
 * Interface to security_compliance_task_runner.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace draiosproto {
class comp_run;
}

namespace dragent
{

/**
 * Interface to objects that can run compliance tasks.
 */
class security_compliance_task_runner
{
public:
	virtual ~security_compliance_task_runner() = default;

	virtual bool run_compliance_tasks(const draiosproto::comp_run& run,
	                                  std::string& errstr) = 0;
};

} // namespace dragent
