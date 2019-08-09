/**
 * @file
 *
 * Interface to security_orchestrator_events_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

class security_host_metadata_receiver;

/**
 * Handles messages of type ORCHESTRATOR_EVENTS that the connection_manager
 * receives from the backend.
 */
class security_orchestrator_events_message_handler : public connection_manager::message_handler
{
public:
	security_orchestrator_events_message_handler(
			security_host_metadata_receiver& receiver);

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;

private:
	security_host_metadata_receiver& m_receiver;
};

} // namespace dragent
