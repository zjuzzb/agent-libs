/**
 * @file
 *
 * Implementation of config_data_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_data_message_handler.h"
#include "common_logger.h"
#include "configuration.h"
#include "protocol.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

config_data_message_handler::config_data_message_handler(
		dragent_configuration& configuration):
	m_configuration(configuration)
{ }

bool config_data_message_handler::handle_message(const draiosproto::message_type,
		                                 uint8_t* const buffer,
		                                 const size_t buffer_size)
{
	if(m_configuration.m_auto_config)
	{
		draiosproto::config_data request;
		bool all_files_handled = true;

		dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &request);

		for(const auto& config_file_proto : request.config_files())
		{
			std::string errstr;

			if(m_configuration.save_auto_config(config_file_proto.name(),
							    config_file_proto.content(),
							    errstr) < 0)
			{
				LOG_ERROR(errstr);
				all_files_handled = false;
			}
		}

		return all_files_handled;
	}
	else
	{
		LOG_DEBUG("Auto config disabled, ignoring CONFIG_DATA message");
		return false;
	}
}

} // namespace dragent
