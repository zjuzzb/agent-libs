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
#include "yaml_configuration.h"

dragent_memdump_logger::dragent_memdump_logger(
		dragent::infra_event_sink* const handler):
	m_event_sink(handler)
{ }

void dragent_memdump_logger::log(const std::string& source,
                                 const std::string& msg)
{
	if(!m_event_sink)
	{
		return;
	}

	const yaml_configuration yaml(msg);

	const uint64_t ts = sinsp_utils::get_current_time_ns();
	const uint64_t tid = 0;
	const std::string name = yaml.get_scalar<std::string>("name");
	const std::string desc = yaml.get_scalar<std::string>("description", "");
	const std::string scope = yaml.get_scalar<std::string>("scope", "");

	m_event_sink->push_infra_event(ts, tid, source, name, desc, scope);
}
