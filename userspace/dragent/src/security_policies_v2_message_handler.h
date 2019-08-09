/**
 * @file
 *
 * Interface to security_policies_v2_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

class security_policy_v2_loader;

/**
 * Handles messages of type POLICIES_V2 that the connection_manager receives
 * from the backend.
 */
class security_policies_v2_message_handler : public connection_manager::message_handler
{
public:
	security_policies_v2_message_handler(
			security_policy_v2_loader& policy_loader);

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* const buffer,
	                    const size_t buffer_size) override;

private:
	security_policy_v2_loader& m_policy_loader;
};

} // namespace dragent
