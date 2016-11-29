#include <string>

#include "falco_events.h"

#include "sinsp_int.h"
#include "logger.h"
#include "user_event.h"
#include "eventformatter.h"

using namespace std;

falco_events::falco_events() :
	m_container_id_formatter(NULL)
{
}

falco_events::~falco_events()
{
	delete(m_container_id_formatter);
}

void falco_events::init(sinsp *inspector, const string &machine_id)
{
	m_inspector = inspector;
	m_machine_id = machine_id;
	m_container_id_formatter = new sinsp_evt_formatter(m_inspector, "container.id=%container.id");
}

void falco_events::generate_user_event(unique_ptr<falco_engine::rule_result> &res)
{
	if(res)
	{
		sinsp_logger::event_severity severity;

		string msg;
		string event_str;
		sinsp_user_event::tag_map_t tags;
		auto match = m_formatter_cache.find(res->rule);
		shared_ptr<sinsp_evt_formatter> formatter;
		if(match == m_formatter_cache.end())
		{
			try {

				formatter = make_shared<sinsp_evt_formatter>(m_inspector, res->format);
				m_formatter_cache[res->rule] = formatter;
			}
			catch (sinsp_exception& e)
			{
				throw falco_exception("Invalid output format '" + res->format + "': '" + string(e.what()) + "'");
			}
		}
		else
		{
			formatter = match->second;
		}
		formatter->tostring(res->evt, &msg);

		// Log as a user event.
		severity = falco_priority_to_severity(res->priority);

		tags["source"] = "falco_engine";

		std::string scope("host.mac=");
		if(falco_events::m_machine_id.length())
		{
			scope.append(m_machine_id);
		}
		else
		{
			scope.clear();
		}

		// Try to extract the container id from the event.

		string container_id;
		m_container_id_formatter->tostring(res->evt, &container_id);

		if(container_id != "container.id=")
		{
			scope.append(" and ");
			scope.append(container_id);
		}

		event_str = sinsp_user_event::to_string(res->evt->get_ts() / ONE_SECOND_IN_NS,
							move(res->rule),
							move(msg),
							move(scope),
							move(tags));
		g_logger.log(event_str, severity);
	}
}

inline sinsp_logger::event_severity falco_events::falco_priority_to_severity(std::string &priority)
{
	if(priority == "EMERGENCY")
	{
		return sinsp_logger::SEV_EVT_EMERGENCY;
	}
	else if(priority == "ALERT")
	{
		// Not an exact match, but allows a 1-1 mapping
		return sinsp_logger::SEV_EVT_FATAL;
	}
	else if(priority == "CRITICAL")
	{
		return sinsp_logger::SEV_EVT_CRITICAL;
	}
	else if(priority == "ERROR")
	{
		return sinsp_logger::SEV_EVT_ERROR;
	}
	else if(priority == "WARNING")
	{
		return sinsp_logger::SEV_EVT_WARNING;
	}
	else if(priority == "NOTICE")
	{
		return sinsp_logger::SEV_EVT_NOTICE;
	}
	else if(priority == "INFO")
	{
		return sinsp_logger::SEV_EVT_INFORMATION;
	}
	else if(priority == "DEBUG")
	{
		return sinsp_logger::SEV_EVT_DEBUG;
	}
	else
	{
		g_logger.log("Unknown falco priority " + priority + ". Using SEV_EVT_WARNING severity ");
		return sinsp_logger::SEV_EVT_WARNING;
	}
}

