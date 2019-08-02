/**
 * @file
 *
 * Implementation of dragent_user_event_callback.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dragent_user_event_callback.h"
#include "common_logger.h"
#include "user_event_logger.h"
#include <Poco/Logger.h>
#include <yaml-cpp/yaml.h>

dragent_user_event_callback::dragent_user_event_callback(
		Poco::Logger& event_logger,
	        const double rate,
	        const double max_tokens):
	m_event_logger(event_logger),
	m_token_bucket()
{
	m_token_bucket.init(rate, max_tokens);
}

void dragent_user_event_callback::log(
		const sinsp_user_event& evt,
		const user_event_logger::severity severity)
{
	std::string str = format_event(evt);

	// For user event severities, only log the event if allowed by
	// the token bucket.
	if(!m_token_bucket.claim())
	{
		g_log->warning("User event throttled: msg=" + str);
		return;
	}

	switch(severity)
	{
	case user_event_logger::SEV_EVT_FATAL:
		m_event_logger.fatal(str);
		break;

	case user_event_logger::SEV_EVT_CRITICAL:
		m_event_logger.critical(str);
		break;

	case user_event_logger::SEV_EVT_ERROR:
		m_event_logger.error(str);
		break;

	case user_event_logger::SEV_EVT_WARNING:
		m_event_logger.warning(str);
		break;

	case user_event_logger::SEV_EVT_NOTICE:
		m_event_logger.notice(str);
		break;

	case user_event_logger::SEV_EVT_INFORMATION:
		m_event_logger.information(str);
		break;

	case user_event_logger::SEV_EVT_DEBUG:
		m_event_logger.debug(str);
		break;

	}
}

std::string dragent_user_event_callback::format_event(const sinsp_user_event &evt)
{
	YAML::Emitter yaml;
	yaml << YAML::BeginMap;
	yaml << YAML::Key << "timestamp" << YAML::Value << evt.epoch_time_s();
	yaml << YAML::Key << "name" << YAML::Value << evt.name();
	yaml << YAML::Key << "description" << YAML::Value << evt.description();
	yaml << YAML::Key << "scope" << YAML::Value << evt.scope();

	if(evt.severity() != sinsp_user_event::UNKNOWN_SEVERITY)
	{
		yaml << YAML::Key << "priority" << YAML::Value << evt.severity();
	}

	if(!evt.tags().empty())
	{
		yaml << YAML::Key << "tags";
		yaml << YAML::Value << YAML::BeginMap;
		for(auto& tag : evt.tags())
		{
			yaml << YAML::Key << tag.first << YAML::Value << tag.second;
		}
		yaml << YAML::EndMap;
	}

	std::string yaml_str = yaml.c_str();
	g_logger.log(yaml_str, sinsp_logger::SEV_DEBUG);
	return yaml_str;
}