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
const std::string SAMPLE_EVENT_STRING = "timestamp: 18446744073709551615\n"
					"name: Event Name\n"
					"description: Event Status\n"
					"scope: host.mac='00:1c:42:9a:bc:53' and container.image='gcr.io/google_containers/kubernetes-dashboard-amd64:v1.5.1' and container.id='4280494e6a4b'\n"
					"tags:\n  source: docker\n";

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

	static sinsp_user_event get_sample_event()
	{
		event_scope scope;
		scope.add("host.mac", "00:1c:42:9a:bc:53");
		scope.add("container.image", "gcr.io/google_containers/kubernetes-dashboard-amd64:v1.5.1");
		std::string id("4280494e6a4b080246199030dcb7cb716f6c6492d8699d58e316ce22e758b573");
		scope.add("container.id", id.substr(0, 12));
		sinsp_user_event::tag_map_t tags{{"source", "docker"}};
		return sinsp_user_event(
			static_cast<uint64_t>(~0),
			"Event Name",
			"Event Status",
			std::move(scope.get_ref()),
			std::move(tags),
			sinsp_user_event::UNKNOWN_SEVERITY);
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
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Fatal: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_FATAL);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_CRITICAL results in a critical log message.
 */
TEST_F(dragent_user_event_logger_test, critical_log)
{
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Critical: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_CRITICAL);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_ERROR results in an error log message.
 */
TEST_F(dragent_user_event_logger_test, error_log)
{
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Error: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_ERROR);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_WARNING results in a warning log message.
 */
TEST_F(dragent_user_event_logger_test, warning_log)
{
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Warning: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_WARNING);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_NOTICE results in a notice log message.
 */
TEST_F(dragent_user_event_logger_test, notice_log)
{
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Notice: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_NOTICE);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_INFORMATION results in an information log message.
 */
TEST_F(dragent_user_event_logger_test, information_log)
{
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Information: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_INFORMATION);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that SEV_EVT_DEBUG results in a debug log message.
 */
TEST_F(dragent_user_event_logger_test, debug_log)
{
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	const std::string expected = "Debug: " + SAMPLE_EVENT_STRING;

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_DEBUG);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that we drop logs if they come in faster than we can handle.
 */
TEST_F(dragent_user_event_logger_test, debug_log_suppressed)
{
	const double max_tokens = 0.0;
	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, max_tokens);

	const std::string expected = "";

	cb.log(get_sample_event(), user_event_logger::SEV_EVT_DEBUG);

	ASSERT_EQ(expected, get_log_output());
}

/**
 * Ensure that we serialize special YAML characters correctly
 */
TEST_F(dragent_user_event_logger_test, yaml_special)
{
	const std::string description = R"yaml(this: is \a "yaml" \"document\" --- for fun & profit *where applicable)yaml";
	const std::string tag_key = R"(key with "quotes" and spaces)";

	event_scope scope;
	scope.add("host.mac", "00:1c:42:9a:bc:53");
	scope.add("container.image", "gcr.io/google_containers/kubernetes-dashboard-amd64:v1.5.1");
	std::string id("4280494e6a4b080246199030dcb7cb716f6c6492d8699d58e316ce22e758b573");
	scope.add("container.id", id.substr(0, 12));
	sinsp_user_event::tag_map_t tags{{tag_key, "va\nlue"}};

	const std::string expected = R"yaml(timestamp: 18446744073709551615
name: Event Name
description: "this: is \\a \"yaml\" \\\"document\\\" --- for fun & profit *where applicable"
scope: host.mac='00:1c:42:9a:bc:53' and container.image='gcr.io/google_containers/kubernetes-dashboard-amd64:v1.5.1' and container.id='4280494e6a4b'
tags:
  key with "quotes" and spaces: "va\nlue"
)yaml";

	dragent_user_event_callback cb(get_logger(), DEFAULT_RATE, DEFAULT_MAX_TOKENS);

	auto event = sinsp_user_event(
		~0ULL,
		"Event Name",
		std::string(description),
		std::move(scope.get_ref()),
		std::move(tags),
		sinsp_user_event::UNKNOWN_SEVERITY);

	cb.log(event, user_event_logger::SEV_EVT_NOTICE);
	ASSERT_EQ("Notice: " + expected, get_log_output());
}
