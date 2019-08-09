/**
 * @file
 *
 * Interface to error_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

/**
 * Handles messages of type ERROR_MESSAGE that the connection_manager receives
 * from the backend.
 */
class error_message_handler : public connection_manager::message_handler
{
public:
	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;
};

} // namespace dragent
