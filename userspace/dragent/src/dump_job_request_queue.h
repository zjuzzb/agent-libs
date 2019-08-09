/**
 * @file
 *
 * Interface to dump_job_request_queue.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "capture_job_handler.h"
#include <memory>

namespace dragent
{

class dump_job_request_queue
{
public:
	virtual ~dump_job_request_queue() = default;

	virtual void queue_job_request(std::shared_ptr<capture_job_handler::dump_job_request> job_request) = 0;
};

} // namespace dragent
