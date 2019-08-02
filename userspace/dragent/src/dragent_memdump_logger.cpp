/**
 * @file
 *
 * Implementation of dragent_memdump_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dragent_memdump_logger.h"
#include "infra_event_sink.h"
#include "utils.h"

dragent_memdump_logger::dragent_memdump_logger(
		dragent::infra_event_sink* const handler):
	m_event_sink(handler)
{ }

void dragent_memdump_logger::log(const std::string& source,
                                 const sinsp_user_event& evt)
{
	if(!m_event_sink)
	{
		return;
	}

	const uint64_t ts = sinsp_utils::get_current_time_ns();
	const uint64_t tid = 0;

	m_event_sink->push_infra_event(ts, tid, source, evt.name(), evt.description(), evt.scope());
}
