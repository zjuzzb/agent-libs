/**
 * @file
 *
 * Interface to config_data_message_handler;
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdint>

namespace dragent
{

/**
 * Interface to objects that can handle config data update messages.
 */
class config_data_message_handler
{
public:
	virtual ~config_data_message_handler() = default;

	/**
	 * Handle the config data update message.
	 *
	 * @param[in] buf  The binary representation of the config data
	 *                 protobuf.
	 * @param[in] size The size of the buf.
	 *
	 * @returns true if handling was successful, false otherwise.
	 */
	virtual bool handle_config_data(const uint8_t* buf, uint32_t size) = 0;
};


} // namespace dragent
