/**
 * @file
 *
 * Interface to security_compliance_run_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

class security_compliance_task_runner;

/**
 * Handles messages of type COMP_RUN that the connection_manager receives from
 * the backend.
 */
class security_compliance_run_message_handler : public connection_manager::message_handler
{
public:
	security_compliance_run_message_handler(security_compliance_task_runner& runner);

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;

private:
	security_compliance_task_runner& m_task_runner;
};

} //namespace dragent
