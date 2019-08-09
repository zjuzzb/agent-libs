/**
 * @file
 *
 * Implementation of security_orchestrator_events_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "security_orchestrator_events_message_handler.h"
#include "common_logger.h"
#include "protocol.h"
#include "security_config.h"
#include "security_host_metadata_receiver.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

security_orchestrator_events_message_handler::security_orchestrator_events_message_handler(
		security_host_metadata_receiver& receiver):
	m_receiver(receiver)
{ }

bool security_orchestrator_events_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
#if !defined(CYGWING_AGENT)
	draiosproto::orchestrator_events evts;

	if(!libsanalyzer::security_config::is_enabled())
	{
		LOG_DEBUG("Security disabled, ignoring ORCHESTRATOR_EVENTS message");
		return false;
	}

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &evts);

	m_receiver.receive_hosts_metadata(evts);
#endif
	return true;
}

} // namespace dragent
