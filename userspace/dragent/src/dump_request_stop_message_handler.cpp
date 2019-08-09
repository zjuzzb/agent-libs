/**
 * @file
 *
 * Implementation of dump_request_stop_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dump_request_stop_message_handler.h"
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

dump_request_stop_message_handler::dump_request_stop_message_handler(
		dump_job_request_queue& queue):
	m_job_request_queue(queue)
{ }

bool dump_request_stop_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
	draiosproto::dump_request_stop request;

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &request);

	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		make_shared<capture_job_handler::dump_job_request>();

	job_request->m_stop_details = make_unique<capture_job_handler::stop_job_details>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_STOP;
	job_request->m_token = request.token();

	// For captures created by the connection manager,
	// m_defer_send is never true, so there isn't any need to
	// worry about stopping a deferred capture. But set this for
	// completeness.
	job_request->m_stop_details->m_remove_unsent_job = false;

	// This could go directly to the capture handler as there's no
	// need to add any state when stopping a job. However, still
	// sending it via the sinsp_worker so there's no chance of the
	// stop message arriving at the capture handler before the
	// start. (Unlikely, but just being safe).
	m_job_request_queue.queue_job_request(job_request);

	return true;
}

} // namespace dragent
