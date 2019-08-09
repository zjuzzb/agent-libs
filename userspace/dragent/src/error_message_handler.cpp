/**
 * @file
 *
 * Implementation of error_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "error_message_handler.h"
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

bool error_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
	draiosproto::error_message err_msg;

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &err_msg);

	std::string err_str = "unknown error";
	bool term = false;

	// Log as much useful info as possible from the error_message
	if(err_msg.has_type())
	{
		const draiosproto::error_type err_type = err_msg.type();

		if(draiosproto::error_type_IsValid(err_type))
		{
			err_str = draiosproto::error_type_Name(err_type);

			if(err_msg.has_description() && !err_msg.description().empty())
			{
				err_str += " (" + err_msg.description() + ")";
			}

			if(err_type == draiosproto::error_type::ERR_INVALID_CUSTOMER_KEY ||
			   err_type == draiosproto::error_type::ERR_PROTO_MISMATCH)
			{
				term = true;
				err_str += ", terminating the agent";
			}
		}
		else
		{
			err_str = ": received invalid error type: " + std::to_string(err_type);
		}
	}

	LOG_ERROR("received " + err_str);

	if(term)
	{
		dragent_configuration::m_terminate = true;
	}

	return true;
}

} // namespace dragent
