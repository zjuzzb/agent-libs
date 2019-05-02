/**
 * @file
 *
 * Implementation of dragent_user_event_callback.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dragent_user_event_callback.h"
#include "logger.h"
#include "token_bucket.h"
#include "user_event_logger.h"
#include <Poco/Logger.h>

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
		std::string&& str,
		const user_event_logger::severity severity)
{
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
