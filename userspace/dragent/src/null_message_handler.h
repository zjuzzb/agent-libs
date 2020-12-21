/**
 * @file
 *
 * Interface to null_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

/**
 * Handles messages that should be ignored.
 */
class null_message_handler : public connection_manager::message_handler
{
public:
	/**
	 * Does nothing. All parameters are ignored. Returns true.
	 */
	bool handle_message(const draiosproto::message_type,
	                    const uint8_t* buffer,
	                    size_t buffer_size) override;
};

} // namespace dragent
