/**
 * @file
 *
 * Interface to security_compliance_calender_receiver.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace draiosproto {
class comp_calendar;
}

namespace dragent
{

/**
 * Interface to objects that can set compliance calendars.
 */
class security_compliance_calender_receiver
{
public:
	virtual ~security_compliance_calender_receiver() = default;

	virtual bool set_compliance_calendar(const draiosproto::comp_calendar& calendar,
	                                     bool send_results,
	                                     bool send_events,
	                                     std::string& errstr) = 0;
};

} // namespace dragent
