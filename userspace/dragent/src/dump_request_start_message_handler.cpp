/**
 * @file
 *
 * Implementation of dump_request_start_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "capture_job_handler.h"
#include "common_logger.h"
#include "dump_job_request_queue.h"
#include "dump_request_start_message_handler.h"
#include "protocol.h"

#include <string>

namespace
{
COMMON_LOGGER();

}  // end namespace

namespace dragent
{
dump_request_start_message_handler::dump_request_start_message_handler(
    dump_job_request_queue& queue)
    : m_job_request_queue(queue)
{
}

bool dump_request_start_message_handler::handle_message(const draiosproto::message_type,
                                                        const uint8_t* const buffer,
                                                        const size_t buffer_size)
{
	draiosproto::dump_request_start request;

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &request);

	std::shared_ptr<capture_job_queue_handler::dump_job_request> job_request =
	    make_shared<capture_job_queue_handler::dump_job_request>();

	job_request->m_start_details = make_unique<capture_job_queue_handler::start_job_details>();

	job_request->m_request_type = capture_job_queue_handler::dump_job_request::JOB_START;
	job_request->m_token = request.token();

	if (request.has_filters())
	{
		job_request->m_start_details->m_filter = request.filters();
	}

	if (request.has_duration_ns())
	{
		job_request->m_start_details->m_duration_ns = request.duration_ns();
	}

	if (request.has_max_size())
	{
		job_request->m_start_details->m_max_size = request.max_size();
	}

	if (request.has_past_duration_ns())
	{
		job_request->m_start_details->m_past_duration_ns = request.past_duration_ns();
	}

	if (request.has_past_size())
	{
		job_request->m_start_details->m_past_size = request.past_size();
	}

	std::string errmsg;
	bool rc = m_job_request_queue.queue_job_request(job_request, errmsg);

	if (!rc)
	{
		LOG_ERROR("Could not queue dump start request: %s", errmsg.c_str());
	}

	return rc;
}

}  // namespace dragent
