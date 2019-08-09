/**
 * @file
 *
 * Implementation of security_compliance_calendar_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "security_compliance_calendar_message_handler.h"
#include "common_logger.h"
#include "protocol.h"
#include "security_compliance_calender_receiver.h"
#include "security_config.h"
#include <string>

namespace
{

COMMON_LOGGER();

} // end namespace

namespace dragent
{

security_compliance_calendar_message_handler::security_compliance_calendar_message_handler(
		security_compliance_calender_receiver& receiver):
	m_receiver(receiver)
{ }

bool security_compliance_calendar_message_handler::handle_message(
		const draiosproto::message_type,
		uint8_t* const buffer,
		const size_t buffer_size)
{
#if !defined(CYGWING_AGENT)
	draiosproto::comp_calendar calendar;
	std::string errstr;

	if(!libsanalyzer::security_config::is_enabled())
	{
		LOG_DEBUG("Security disabled, ignoring COMP_CALENDAR message");
		return false;
	}

	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &calendar);

	if (!m_receiver.set_compliance_calendar(
				calendar,
				libsanalyzer::security_config::get_send_compliance_results(),
				libsanalyzer::security_config::get_send_compliance_events(),
				errstr))
	{
		LOG_ERROR("Could not set compliance calendar: " + errstr);
		return false;
	}
#endif

	return true;
}

} // namespace dragent
