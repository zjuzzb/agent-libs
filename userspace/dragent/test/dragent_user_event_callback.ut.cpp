/**
 * @file
 *
 * Unit tests for dragent_user_event_callback.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dragent_user_event_callback.h"
#include "common_logger.h"
#include "user_event_logger.h"
#include <string>
#include <gtest.h>
#include <Poco/AutoPtr.h>
#include <Poco/FormattingChannel.h>
#include <Poco/Logger.h>
#include <Poco/Message.h>
#include <Poco/PatternFormatter.h>
#include <Poco/StreamChannel.h>


namespace
{

const std::string LOGGER_NAME = "dragent_user_event_logger_test";
const double DEFAULT_RATE = 1.0;
const double DEFAULT_MAX_TOKENS = 100.0;
const std::string DEFAULT_LOG_MESSAGE = "This is a log message";

} // end namespace

class dragent_user_event_logger_test : public testing::Test
{
public:
	dragent_user_event_logger_test() :
		m_out(nullptr),
		m_logger(nullptr)
	{ }

	void SetUp() override
	{
		m_out = new std::stringstream();

		Poco::AutoPtr<Poco::Formatter> formatter(
				new Poco::PatternFormatter("%p: %t"));
		Poco::AutoPtr<Poco::Channel> stream_channel(
				new Poco::StreamChannel(*m_out));
		Poco::AutoPtr<Poco::Channel> formatting_channel(
				new Poco::FormattingChannel(formatter, stream_channel));

		Poco::Logger& logger = Poco::Logger::create(LOGGER_NAME,
		                                            formatting_channel,
		                                            Poco::Message::Priority::PRIO_DEBUG);
		m_logger = &logger;

	}

	void TearDown() override
	{
		m_logger = nullptr;
		Poco::Logger::destroy(LOGGER_NAME);

		delete m_out;
		m_out = nullptr;
	}

protected:
	Poco::Logger& get_logger()
	{
		return *m_logger;
	}

	std::string get_log_output()
	{
		return m_out->str();
	}

private:
	std::stringstream* m_out;
	Poco::Logger* m_logger;
};

/**
 * Ensure that SEV_EVT_FATAL results in a fatal log message.
 */
TEST_F(dragent_user_event_logger_test, fatal_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Fatal: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_FATAL);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_CRITICAL results in a critical log message.
 */
TEST_F(dragent_user_event_logger_test, critial_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Critical: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_CRITICAL);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_ERROR results in an error log message.
 */
TEST_F(dragent_user_event_logger_test, error_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Error: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_ERROR);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_WARNING results in a warning log message.
 */
TEST_F(dragent_user_event_logger_test, warning_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Warning: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_WARNING);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_NOTICE results in a notice log message.
 */
TEST_F(dragent_user_event_logger_test, notice_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Notice: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_NOTICE);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_INFORMATION results in an information log message.
 */
TEST_F(dragent_user_event_logger_test, information_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Information: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_INFORMATION);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_DEBUG results in a debug log message.
 */
TEST_F(dragent_user_event_logger_test, debug_log)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Debug: " + log_message + "\n";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_DEBUG);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that we drop logs if they come in faster than we can handle.
 */
TEST_F(dragent_user_event_logger_test, debug_log_suppressed)
{
	std::string log_message = DEFAULT_LOG_MESSAGE;
	const double max_tokens = 0.0;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, max_tokens);

	const std::string expected = "";

	cb.log(std::move(log_message), user_event_logger::SEV_EVT_DEBUG);

	ASSERT_EQ(expected, get_log_output());
}
