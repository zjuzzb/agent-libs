/**
 * @file
 *
 * Interface to dump_job_request_queue.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <memory>

namespace capture_job_queue_handler
{
class dump_job_request;
}

namespace dragent
{
class dump_job_request_queue
{
public:
	virtual ~dump_job_request_queue() = default;

	/**
	 * queue a job request
	 */
	virtual bool queue_job_request(
	    std::shared_ptr<capture_job_queue_handler::dump_job_request> job_request,
	    std::string& errmsg) = 0;
};

}  // namespace dragent
