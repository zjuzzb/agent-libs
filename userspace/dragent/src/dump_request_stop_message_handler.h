/**
 * @file
 *
 * Interface to dump_request_stop_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

class dump_job_request_queue;

/**
 * Handles messages of type DUMP_REQUEST_STOP that the connection_manager
 * receives from the backend.
 */
class dump_request_stop_message_handler : public connection_manager::message_handler
{
public:
	dump_request_stop_message_handler(dump_job_request_queue& queue);

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;

private:
	dump_job_request_queue& m_job_request_queue;
};

} // namespace dragent
