/**
 * @file
 *
 * Implementation of config_data_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_data_message_handler.h"
#include "config_update.h"
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
		                                 const uint8_t* const buffer,
		                                 const size_t buffer_size)
{
	if(m_configuration.m_auto_config)
	{
		draiosproto::config_data request;
		bool all_files_handled = true;
		bool config_updated = false;

		dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &request);

		for(const auto& config_file_proto : request.config_files())
		{
			std::string errstr;

			const int rc = m_configuration.save_auto_config(
					config_file_proto.name(),
					config_file_proto.content(),
					errstr);

			if(rc > 0)
			{
				config_updated = true;
			}
			else if(rc < 0)
			{
				LOG_ERROR("%s", errstr.c_str());
				all_files_handled = false;
			}

		}

		config_update::set_updated(config_updated);

		return all_files_handled;
	}
	else
	{
		LOG_INFO("Auto config disabled, ignoring CONFIG_DATA message");
		config_update::set_updated(false);
		return false;
	}
}

} // namespace dragent
