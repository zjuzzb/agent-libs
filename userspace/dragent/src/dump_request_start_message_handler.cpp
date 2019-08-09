/**
 * @file
 *
 * Implementation of dump_request_start_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dump_request_start_message_handler.h"
#include "common_logger.h"
#include "dump_job_request_queue.h"
#include "protocol.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

dump_request_start_message_handler::dump_request_start_message_handler(
		dump_job_request_queue& queue):
	m_job_request_queue(queue)
{ }

bool dump_request_start_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
	draiosproto::dump_request_start request;

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &request);

	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		make_shared<capture_job_handler::dump_job_request>();

	job_request->m_start_details = make_unique<capture_job_handler::start_job_details>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_START;
	job_request->m_token = request.token();

	if(request.has_filters())
	{
		job_request->m_start_details->m_filter = request.filters();
	}

	if(request.has_duration_ns())
	{
		job_request->m_start_details->m_duration_ns = request.duration_ns();
	}

	if(request.has_max_size())
	{
		job_request->m_start_details->m_max_size = request.max_size();
	}

	if(request.has_past_duration_ns())
	{
		job_request->m_start_details->m_past_duration_ns = request.past_duration_ns();
	}

	if(request.has_past_size())
	{
		job_request->m_start_details->m_past_size = request.past_size();
	}

	// Note: sending request via sinsp_worker so it can add on
	// needed state (e.g. sinsp_dumper)
	m_job_request_queue.queue_job_request(job_request);

	return true;
}

} // namespace dragent
