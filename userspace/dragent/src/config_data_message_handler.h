/**
 * @file
 *
 * Interface to config_data_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

class dragent_configuration;

namespace dragent
{

/**
 * Handles messages of type CONFIG_DATA that the connection_manager receives
 * from the backend.
 */
class config_data_message_handler : public connection_manager::message_handler
{
public:
	config_data_message_handler(dragent_configuration& configuration);

	bool handle_message(const draiosproto::message_type,
	                    const uint8_t* buffer,
	                    size_t buffer_size) override;

private:
	dragent_configuration& m_configuration;
};

} // namespace dragent
