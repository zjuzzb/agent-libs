/**
 * @file
 *
 * Implementation of security_compliance_run_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "security_compliance_run_message_handler.h"
#include "common_logger.h"
#include "protocol.h"
#include "security_compliance_task_runner.h"
#include "security_config.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

security_compliance_run_message_handler::security_compliance_run_message_handler(
		security_compliance_task_runner& runner):
	m_task_runner(runner)
{ }

bool security_compliance_run_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
#if !defined(CYGWING_AGENT)
	draiosproto::comp_run run;
	std::string errstr;

	if(!libsanalyzer::security_config::is_enabled())
	{
		LOG_DEBUG("Security disabled, ignoring COMP_RUN message");
		return false;
	}

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &run);

	if (!m_task_runner.run_compliance_tasks(run, errstr))
	{
		LOG_ERROR("Could not run compliance tasks: " + errstr);
		return false;
	}
#endif

	return true;
}

} //namespace dragent
