/**
 * @file
 *
 * Implementation of null_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

#include "null_message_handler.h"

namespace dragent
{

bool null_message_handler::handle_message(const draiosproto::message_type,
                                          uint8_t* const,
                                          const size_t)
{
	return true;
}

} // namespace dragent

