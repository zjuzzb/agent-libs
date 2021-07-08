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
#include "prom_config_file_manager.h"
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

			LOG_INFO("Received config file: %s", config_file_proto.name().c_str());

			if ((config_file_proto.type() == draiosproto::config_file_type::PROM_LOCAL_CONFIG) ||
				(config_file_proto.type() == draiosproto::config_file_type::PROM_CLUSTER_CONFIG) ||
				(config_file_proto.type() == draiosproto::config_file_type::PROM_CLUSTER_RULES))
			{
				LOG_DEBUG("prom config proto: %s", config_file_proto.DebugString().c_str());
				prom_config_file_manager::instance()->save_config(config_file_proto, errstr);
				LOG_DEBUG("called save_prom_config, errstr: %s", errstr.c_str());
				continue;
			}

			const int rc = m_configuration.save_auto_config(
					config_file_proto.name(),
					config_file_proto.content(),
					errstr);

			if(rc > 0)
			{
				config_updated = true;
				// Temporary log message
				LOG_INFO("Write to config file %s done",
				         config_file_proto.name().c_str());
			}
			else if(rc < 0)
			{
				LOG_ERROR("Write to config file %s failed: %s",
				          config_file_proto.name().c_str(),
				          errstr.c_str());
				all_files_handled = false;
			}
			else
			{
				// Temporary log message
				LOG_INFO("No write needed for config file %s",
				         config_file_proto.name().c_str());
			}
		}
		prom_config_file_manager::instance()->update_files();

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
