/**
 * @file
 *
 * Interface to security_compliance_calendar_message_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "connection_manager.h"
#include "draios.pb.h"

namespace dragent
{

class security_compliance_calender_receiver;

/**
 * Handles messages of type COMP_CALENDAR that the connection_manager receives
 * from the backend.
 */
class security_compliance_calendar_message_handler : public connection_manager::message_handler
{
public:
	security_compliance_calendar_message_handler(
			security_compliance_calender_receiver& receiver);

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;

private:
	security_compliance_calender_receiver& m_receiver;
};

} // namespace dragent
