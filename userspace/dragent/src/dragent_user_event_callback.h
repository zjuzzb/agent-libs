/**
 * @file
 *
 * Interface to dragent_user_event_callback.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "user_event_logger.h"
#include "token_bucket.h"

namespace Poco
{
class Logger;
}

/**
 * A concrete user_event_logger::callback that writes rate-limited user event
 * logs to a Poco logger.
 */
class dragent_user_event_callback : public user_event_logger::callback
{
public:
	dragent_user_event_callback(Poco::Logger& event_logger,
	                            double rate,
	                            double max_tokens);

	void log(const sinsp_user_event& evt,
	         user_event_logger::severity severity) override;

private:
	static std::string format_event(const sinsp_user_event& evt);

	Poco::Logger& m_event_logger;
	token_bucket m_token_bucket;
};

