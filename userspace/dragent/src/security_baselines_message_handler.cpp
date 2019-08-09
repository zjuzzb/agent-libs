/**
 * @file
 *
 * Implementation of security_baselines_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "security_baselines_message_handler.h"
#include "common_logger.h"
#include "protocol.h"
#include "security_config.h"
#include "security_baselines_loader.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

security_baselines_message_handler::security_baselines_message_handler(
		security_baselines_loader& loader):
	m_baseline_loader(loader)
{ }

bool security_baselines_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
#if !defined(CYGWING_AGENT)
	draiosproto::baselines baselines;
	std::string errstr;

	if(!libsanalyzer::security_config::is_enabled())
	{
		LOG_DEBUG("Security disabled, ignoring BASELINES message");
		return false;
	}

	if(libsanalyzer::security_config::get_baselines_file() != "")
	{
		LOG_INFO("Security baselines file configured in dragent.yaml, "
		         "ignoring BASELINES message");
		return false;
	}

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &baselines);

	if (!m_baseline_loader.load_baselines(baselines, errstr))
	{
		LOG_ERROR("Could not load baselines message: " + errstr);
		return false;
	}
#endif

	return true;
}

} // namespace dragent
