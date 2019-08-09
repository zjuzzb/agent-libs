/**
 * @file
 *
 * Implementation of security_policies_v2_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "security_policies_v2_message_handler.h"
#include "common_logger.h"
#include "configuration.h"
#include "protocol.h"
#include "security_config.h"
#include "security_policy_v2_loader.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

security_policies_v2_message_handler::security_policies_v2_message_handler(
		security_policy_v2_loader& policy_loader):
	m_policy_loader(policy_loader)
{ }

bool security_policies_v2_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
#if !defined(CYGWING_AGENT)
	draiosproto::policies_v2 policies_v2;
	std::string errstr;

	if(!libsanalyzer::security_config::is_enabled())
	{
		LOG_DEBUG("Security disabled, ignoring POLICIES message");
		return false;
	}

	if(libsanalyzer::security_config::get_policies_v2_file() != "")
	{
		LOG_INFO("Security policies file configured in dragent.yaml, "
		         "ignoring POLICIES_V2 message");
		return false;
	}

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &policies_v2);

	if (!m_policy_loader.load_policies_v2(policies_v2, errstr))
	{
		LOG_ERROR("Could not load policies_v2 message: " + errstr);
		return false;
	}
#endif

	return true;
}

} // namespace dragent
