/**
 * @file
 *
 * Interface to security_baselines_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

class security_baselines_loader;

/**
 * Handles messages of type BASELINES that the connection_manager receives from
 * the backend.
 */
class security_baselines_message_handler : public connection_manager::message_handler
{
public:
	security_baselines_message_handler(security_baselines_loader& loader);

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;

private:
	security_baselines_loader& m_baseline_loader;
};

} // namespace dragent
