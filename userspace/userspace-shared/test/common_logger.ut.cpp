#include "common_logger.h"
#include <map>
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

const std::string FILE_LOGGER_NAME = "common_common_logger_test_file";
const std::string CONSOLE_LOGGER_NAME = "common_common_logger_test_console";
const std::string FILENAME = "test_filename.cpp";
const std::string STRIPPED_FILENAME = "test_filename";
const std::string DEFAULT_COMPONENT = "test:dragent";
const std::string DEFAULT_MESSAGE = "This is a typical log message.";
const std::string TEST_COMPONENT_A = "test_componentA";
const std::string TEST_COMPONENT_B = "test_componentB";
const std::string COMPONENTA_OVERRIDE_CONFIG_DEBUG = "test_componentA: debug";
const std::string COMPONENTA_OVERRIDE_CONFIG_CRITICAL = "test_componentA: critical";
const std::string COMPONENTA_FILE_OVERRIDE_CONFIG_DEBUG = "test_componentA:test_filename: debug";
const std::string MESSAGE_A = "Message from Component A";
const std::string DEBUG_MESSAGE_A = "Debug: Message from Component A\n";

#if _DEBUG
const bool EMIT_DEBUG_LOG = true;
#else
const bool EMIT_DEBUG_LOG = false;
#endif

using prio_map_t = std::map<Poco::Message::Priority, std::string>;
static const prio_map_t s_prio_map = {
	{ Poco::Message::Priority::PRIO_TRACE,       "Trace"       },
	{ Poco::Message::Priority::PRIO_DEBUG,       "Debug"       },
	{ Poco::Message::Priority::PRIO_INFORMATION, "Information" },
	{ Poco::Message::Priority::PRIO_NOTICE,      "Notice"      },
	{ Poco::Message::Priority::PRIO_WARNING,     "Warning"     },
	{ Poco::Message::Priority::PRIO_ERROR,       "Error"       },
	{ Poco::Message::Priority::PRIO_CRITICAL,    "Critical"    },
	{ Poco::Message::Priority::PRIO_FATAL,       "Fatal"       },
};

/**
 * Generate a sample log line with the given priority, line number, and
 * log message.  This should format things like log_sink::stream_log_output
 */
std::string generateMessage(const Poco::Message::Priority priority,
                            const int line,
                            const std::string& message = DEFAULT_MESSAGE,
                            const bool emitLog = true,
			    const std::string& component = DEFAULT_COMPONENT)
{
	std::string log;

	if(emitLog)
	{
		prio_map_t::const_iterator itr = s_prio_map.find(priority);

		if (itr != s_prio_map.end()) {
			log = itr->second;
		}

		const std::string opt_separator = (component.empty() ? "" : ":");

		// 8, test:dragent:test_filename:29: hello, world\n
		log += ": " + component + opt_separator +
		              STRIPPED_FILENAME +
		       ":"  + std::to_string(line) +
		       ": " + message +
		       "\n";
	}

	return log;
}

std::string generateMessage(const Poco::Message::Priority priority,
                            const std::string& message)
{
	std::string log;
	prio_map_t::const_iterator itr = s_prio_map.find(priority);

	if (itr != s_prio_map.end()) {
		log = itr->second;
	}

	log += ": " + message + "\n";

	return log;
}

class common_logger_test : public testing::Test
{
public:
	common_logger_test() :
		m_file_out(),
		m_console_out(),
		s_log_sink(FILENAME, DEFAULT_COMPONENT)
	{ }

	void SetUp() override
	{
		Poco::AutoPtr<Poco::Formatter> file_formatter(
				new Poco::PatternFormatter("%p: %t"));
		Poco::AutoPtr<Poco::Channel> file_stream_channel(
				new Poco::StreamChannel(m_file_out));
		Poco::AutoPtr<Poco::Channel> file_formatting_channel(
				new Poco::FormattingChannel(file_formatter,
				                            file_stream_channel));

		m_file_logger = &Poco::Logger::create(FILE_LOGGER_NAME,
		                                      file_formatting_channel,
		                                      Poco::Message::Priority::PRIO_TRACE);

		Poco::AutoPtr<Poco::Formatter> console_formatter(
				new Poco::PatternFormatter("%p: %t"));
		Poco::AutoPtr<Poco::Channel> console_stream_channel(
				new Poco::StreamChannel(m_console_out));
		Poco::AutoPtr<Poco::Channel> console_formatting_channel(
				new Poco::FormattingChannel(console_formatter,
				                            console_stream_channel));

		m_console_logger = &Poco::Logger::create(CONSOLE_LOGGER_NAME,
		                                         console_formatting_channel,
		                                         Poco::Message::Priority::PRIO_TRACE);

		m_old_log = std::move(g_log);
		std::vector<std::string> dummy_file_config;
		std::vector<std::string> dummy_console_config;
		g_log = std::unique_ptr<common_logger>(
				new common_logger(m_file_logger,
				                  m_console_logger,
				                  Poco::Message::Priority::PRIO_TRACE,
				                  Poco::Message::Priority::PRIO_TRACE,
				                  dummy_file_config,
				                  dummy_console_config));
	}

	void TearDown() override
	{
		::g_log = std::move(m_old_log);

		Poco::Logger::destroy(CONSOLE_LOGGER_NAME);
		Poco::Logger::destroy(FILE_LOGGER_NAME);

		m_file_out.str("");
		m_file_out.clear();

		m_console_out.str("");
		m_console_out.clear();

		m_console_logger = nullptr;
		m_file_logger = nullptr;
	}

	std::stringstream m_file_out;
	std::stringstream m_console_out;

	// This is named 's_log_sink' even though the object isn't static.
	// The rationale for this is that the logging API expects there to
	// be a global static with that name.  In the context of the unit
	// test, we don't want that global static.  Instead, we define it
	// here with the expected name.
	log_sink s_log_sink;

	void set_log_level(const Poco::Message::Priority level)
	{
		if(m_file_logger != nullptr)
		{
			g_log->set_file_log_priority(level);
		}

		if(m_console_logger != nullptr)
		{
			g_log->set_console_log_priority(level);
		}
	}

	// This version of set_log_level supports independent values for the file_level and console_level
	// In the production system, these values are defined in dragent.yaml as file_priority and console_priority.
	void set_log_level(const Poco::Message::Priority file_level, const Poco::Message::Priority console_level)
	{
		if(m_file_logger != nullptr)
		{
			g_log->set_file_log_priority(file_level);
		}

		if(m_console_logger != nullptr)
		{
			g_log->set_console_log_priority(console_level);
		}
	}


private:
	std::unique_ptr<common_logger> m_old_log;
	Poco::Logger* m_file_logger;
	Poco::Logger* m_console_logger;
};

} // end namespace

TEST_F(common_logger_test, log_trace_macro)
{
	// Note for this and other tests in this file, it is important to keep
	// the line number recording and the call to the logging API on the
	// same line.
	const int line = __LINE__; LOG_TRACE("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_TRACE, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_debug_macro)
{
	const int line = __LINE__; LOG_DEBUG("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_info_macro)
{
	const int line = __LINE__; LOG_INFO("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_INFORMATION, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_notice_macro)
{
	const int line = __LINE__; LOG_NOTICE("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_NOTICE, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_warning_macro)
{
	const int line = __LINE__; LOG_WARNING("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_WARNING, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_error_macro)
{
	const int line = __LINE__; LOG_ERROR("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_ERROR, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_critical_macro)
{
	const int line = __LINE__; LOG_CRITICAL("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_CRITICAL, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_fatal_macro)
{
	const int line = __LINE__; LOG_FATAL("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_FATAL, line);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

/**
 * A test that will force the logging API to reallocate a larger buffer.
 */
TEST_F(common_logger_test, larger_than_deafult_max)
{
	const std::string message(2 * log_sink::DEFAULT_LOG_STR_LENGTH, 'a');
	const int line = __LINE__; LOG_FATAL("%s", message.c_str());

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_FATAL, line, message);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

/**
 * Ensure that if we pass a string that contains printf-style placeholders
 * without any additional arguments, that the std::string version of log()
 * gets called, and that the log contains the literal placeholders (i.e.,
 * nothing along the way tries to fill those placeholders, reading random
 * data off the stack.
 */
TEST_F(common_logger_test, string_with_placeholders_no_values)
{
	const std::string message = "This %s is %d a %f test %zu";
	const int line = __LINE__; LOG_FATAL(message);

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_FATAL, line, message);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, empty_component_name_no_colon)
{
	const std::string component = "";
	const Poco::Message::Priority priority = Poco::Message::Priority::PRIO_FATAL;
	const bool emitLog = true;
	const int line = 42; // Some example line number, value is not important
	log_sink local_log_sink(FILENAME, component);

	// Call the API directly instead of via the macro since this
	// test uses a non-standard logger
	local_log_sink.log(priority, line, "%s", DEFAULT_MESSAGE.c_str());
	const std::string expected_message =
		generateMessage(priority, line, DEFAULT_MESSAGE, emitLog, component);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_trace_macro)
{
	const int line = __LINE__; DBG_LOG_TRACE("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_TRACE,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_debug_macro)
{
	const int line = __LINE__; DBG_LOG_DEBUG("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_DEBUG,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_info_macro)
{
	const int line = __LINE__; DBG_LOG_INFO("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_INFORMATION,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_notice_macro)
{
	const int line = __LINE__; DBG_LOG_NOTICE("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_NOTICE,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_warning_macro)
{
	const int line = __LINE__; DBG_LOG_WARNING("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_WARNING,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_error_macro)
{
	const int line = __LINE__; DBG_LOG_ERROR("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_ERROR,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_critical_macro)
{
	const int line = __LINE__; DBG_LOG_CRITICAL("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_CRITICAL,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, dbg_fatal_macro)
{
	const int line = __LINE__; DBG_LOG_FATAL("%s", DEFAULT_MESSAGE.c_str());

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_FATAL,
			                line,
			                DEFAULT_MESSAGE,
			                EMIT_DEBUG_LOG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, trace)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_TRACE,
			                DEFAULT_MESSAGE);
	g_log->trace(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, debug)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_DEBUG,
			                DEFAULT_MESSAGE);
	g_log->debug(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, information)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_INFORMATION,
			                DEFAULT_MESSAGE);
	g_log->information(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, notice)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_NOTICE,
			                DEFAULT_MESSAGE);
	g_log->notice(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, warning)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_WARNING,
			                DEFAULT_MESSAGE);
	g_log->warning(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, error)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_ERROR,
			                DEFAULT_MESSAGE);
	g_log->error(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, critical)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_CRITICAL,
			                DEFAULT_MESSAGE);
	g_log->critical(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, fatal)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_FATAL,
			                DEFAULT_MESSAGE);
	g_log->fatal(DEFAULT_MESSAGE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, trace_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_TRACE,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_TRACE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, debug_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_DEBUG,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_DEBUG);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, information_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_INFORMATION,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_INFO);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, notice_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_NOTICE,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_NOTICE);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, warning_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_WARNING,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_WARNING);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, error_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_ERROR,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_ERROR);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, critical_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_CRITICAL,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_CRITICAL);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, fatal_callback)
{
	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_FATAL,
			                DEFAULT_MESSAGE);
	std::string message = DEFAULT_MESSAGE;

	common_logger::sinsp_logger_callback(std::move(message),
	                                      sinsp_logger::SEV_FATAL);
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_sink_build)
{
	const std::string expected_message = "Hello, world!";
	const std::string log = s_log_sink.build("%s", expected_message.c_str());

	ASSERT_EQ(expected_message, log);
}

TEST_F(common_logger_test, log_level_debug)
{
	set_log_level(Poco::Message::Priority::PRIO_DEBUG);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_DEBUG,
			                DEFAULT_MESSAGE);
	g_log->trace(DEFAULT_MESSAGE);
	g_log->debug(DEFAULT_MESSAGE);
	g_log->trace(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_level_information)
{
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_INFORMATION,
			                DEFAULT_MESSAGE);
	g_log->debug(DEFAULT_MESSAGE);
	g_log->information(DEFAULT_MESSAGE);
	g_log->debug(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_level_notice)
{
	set_log_level(Poco::Message::Priority::PRIO_NOTICE);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_NOTICE,
			                DEFAULT_MESSAGE);
	g_log->information(DEFAULT_MESSAGE);
	g_log->notice(DEFAULT_MESSAGE);
	g_log->information(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_level_warning)
{
	set_log_level(Poco::Message::Priority::PRIO_WARNING);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_WARNING,
			                DEFAULT_MESSAGE);
	g_log->notice(DEFAULT_MESSAGE);
	g_log->warning(DEFAULT_MESSAGE);
	g_log->notice(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_level_error)
{
	set_log_level(Poco::Message::Priority::PRIO_ERROR);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_ERROR,
			                DEFAULT_MESSAGE);
	g_log->warning(DEFAULT_MESSAGE);
	g_log->error(DEFAULT_MESSAGE);
	g_log->warning(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_level_critical)
{
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_CRITICAL,
			                DEFAULT_MESSAGE);
	g_log->error(DEFAULT_MESSAGE);
	g_log->critical(DEFAULT_MESSAGE);
	g_log->error(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, log_level_fatal)
{
	set_log_level(Poco::Message::Priority::PRIO_FATAL);

	const std::string expected_message =
			generateMessage(Poco::Message::Priority::PRIO_FATAL,
			                DEFAULT_MESSAGE);
	g_log->error(DEFAULT_MESSAGE);
	g_log->fatal(DEFAULT_MESSAGE);
	g_log->error(DEFAULT_MESSAGE);

	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, is_enabled_trace)
{
	set_log_level(Poco::Message::Priority::PRIO_TRACE);

	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, is_enabled_debug)
{
	set_log_level(Poco::Message::Priority::PRIO_DEBUG);

	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, is_enabled_information)
{
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);

	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, is_enabled_warning)
{
	set_log_level(Poco::Message::Priority::PRIO_WARNING);

	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, is_enabled_error)
{
	set_log_level(Poco::Message::Priority::PRIO_ERROR);

	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, is_enabled_critical)
{
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL);

	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, is_enabled_fatal)
{
	set_log_level(Poco::Message::Priority::PRIO_FATAL);

	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_TRACE));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_FALSE(g_log->is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(g_log->is_enabled(Poco::Message::Priority::PRIO_FATAL));
}

TEST_F(common_logger_test, component_overrides_none_file)
{
	// set default log level to info
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);

	// no component override, component priority should match default
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_FILE),
			Poco::Message::Priority::PRIO_INFORMATION);

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_TRACE, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_TRACE,       // sev
			 		    Poco::Message::Priority::PRIO_TRACE,       // file_sev
			 		    Poco::Message::Priority::PRIO_TRACE);      // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_DEBUG);
	// We do not expect to see this sev Debug message because the global log level is PRIO_INFORMATION
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_none_console)
{
	// set default log level to info
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);

	// no component override, component priority should match default
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_CONSOLE),
			Poco::Message::Priority::PRIO_INFORMATION);

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_TRACE, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_TRACE,       // sev
			 		    Poco::Message::Priority::PRIO_TRACE,       // file_sev
			 		    Poco::Message::Priority::PRIO_TRACE);      // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_DEBUG);
	// We do not expect to see this sev Debug message because the global log level is PRIO_INFORMATION
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_none_file_debug_console_fatal)
{
	// set default log level for file to debug, console to fatal
	set_log_level(Poco::Message::Priority::PRIO_DEBUG, Poco::Message::Priority::PRIO_FATAL);

	// no component override, component priority should match default
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_FILE),
			Poco::Message::Priority::PRIO_DEBUG);
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_CONSOLE),
			Poco::Message::Priority::PRIO_FATAL);

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_FATAL);      // console_sev

 	ASSERT_EQ(expected_message, m_file_out.str());
  	ASSERT_EQ("", m_console_out.str());
	// generate a PRIO_TRACE message through the g_log->log() interface:
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_TRACE);
	// We do not expect to see the new message in either the file log or the console log:
	ASSERT_EQ((expected_message), m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_none_file_fatal_console_debug)
{
	// set default log level for file to fatal, console to debug
	set_log_level(Poco::Message::Priority::PRIO_FATAL, Poco::Message::Priority::PRIO_DEBUG);

	// no component override, component priority should match default
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_FILE),
			Poco::Message::Priority::PRIO_FATAL);
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_CONSOLE),
			Poco::Message::Priority::PRIO_DEBUG);

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_FATAL,       // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev

	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
	// generate a PRIO_TRACE message through the g_log->log() interface:
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_TRACE);
	// We do not expect see to the new message in either the file log or the console log:
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ((expected_message), m_console_out.str());
}

TEST_F(common_logger_test, component_none_file_fatal_console_fatal)
{
	// set default log level to fatal
	set_log_level(Poco::Message::Priority::PRIO_FATAL);

	// no component override, component priority should match default
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_FILE),
			Poco::Message::Priority::PRIO_FATAL);
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_CONSOLE),
			Poco::Message::Priority::PRIO_FATAL);

	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_TRACE, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_TRACE,       // sev
			 		    Poco::Message::Priority::PRIO_FATAL,       // file_sev
			 		    Poco::Message::Priority::PRIO_FATAL);      // console_sev

	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_DEBUG);
	// Because it is a sev Debug level message, and both logs are set to PRIO_FATAL,
	// the message is suppressed.
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_file)
{
	// set default log level to info
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);

	// set a component override to debug
	std::vector<std::string> config_vector;
	config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);
	g_log->init_log_component_priorities(config_vector, LOG_FILE);

	// component priority should match override value
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_FILE),
			Poco::Message::Priority::PRIO_DEBUG);

	// component priority of component that has no override should have default level
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_B, LOG_FILE),
			Poco::Message::Priority::PRIO_INFORMATION);

	// messages above default level should not be visible via g_log->log(),
	// but should be visible via g_log->log_check_component_priority()
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_INFORMATION);// console_sev
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_DEBUG);
	ASSERT_EQ(expected_message, m_file_out.str());
	// Suppressed because console_sev of PRIO_INFORMATION overrides generateMessage of PRIO_DEBUG
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_console)
{
	// set default log level to info
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);

	// set a component override to debug
	std::vector<std::string> config_vector;
	config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG); // "test_componentA: debug"
	g_log->init_log_component_priorities(config_vector, LOG_CONSOLE);

	// component priority should match override value
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_A, LOG_CONSOLE),
			Poco::Message::Priority::PRIO_DEBUG);

	// component priority of component that has no override should have default level
	ASSERT_EQ(g_log->get_component_priority(TEST_COMPONENT_B, LOG_CONSOLE),
			Poco::Message::Priority::PRIO_INFORMATION);

	// messages above default level should not be visible via g_log->log(),
	// but should be visible via g_log->log_check_component_priority()
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_INFORMATION, // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev
	g_log->log(MESSAGE_A, Poco::Message::Priority::PRIO_DEBUG);

	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_0)
{   
	// This is the first test in a group of component_overrides_g_log_case tests: 0 through 9 and f.
	// The truth table used for the four Precondition state variables as they toggle between critical
	// and debug has 16 total combinations.  We have implemented cases 0 through 8, and skipped 9
	// through E (hexadecimal), but implemented case F. It is redundant to implement 9 through E,
	// after covering cases 0 through 8.
	//
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:    critical
	// console_priority:              critical
	// console_priority_by_component: critical
	// =======================================
	// Expected results:
	// file log:                    suppressed
	// console log:                 suppressed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_CRITICAL);

	// Set component override vectors for the file and console
	// Note: although for test case 0 the two config vectors are identical, we are establishing
	// a pattern where the contents are changed from test case 0 to test case f as they alternate
	// test_component_A between priority debug and critical.
	// Also note for all the test cases in this group, the message is emitted with sev PRIO_DEBUG.
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL);    // "test_componentA: critical"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL); // "test_componentA: critical"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_CRITICAL,    // file_sev
			 		    Poco::Message::Priority::PRIO_CRITICAL);   // console_sev
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_1)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:    critical
	// console_priority:              critical
	// console_priority_by_component:    debug
	// =======================================
	// Expected results:
	// file log:                    suppressed
	// console log:                  displayed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_CRITICAL);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL); // "test_componentA: critical"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG); // "test_componentA: debug"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_CRITICAL,    // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_2)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:    critical
	// console_priority:                 debug
	// console_priority_by_component: critical
	// =======================================
	// Expected results:
	// file log:                    suppressed
	// console log:                 suppressed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_DEBUG);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL);    // "test_componentA: critical"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL); // "test_componentA: critical"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_CRITICAL,    // file_sev
			 		    Poco::Message::Priority::PRIO_CRITICAL);   // console_sev
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_3)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:    critical
	// console_priority:                 debug
	// console_priority_by_component:    debug
	// =======================================
	// Expected results:
	// file log:                    suppressed
	// console log:                  displayed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_DEBUG);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL);    // "test_componentA: critical"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);    // "test_componentA: debug"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_CRITICAL,    // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_4)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:       debug
	// console_priority:              critical
	// console_priority_by_component: critical
	// =======================================
	// Expected results:
	// file log:                     displayed
	// console log:                 suppressed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_CRITICAL);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);       // "test_componentA: debug"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL); // "test_componentA: critical"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_CRITICAL);   // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_5)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:       debug
	// console_priority:              critical
	// console_priority_by_component:    debug
	// =======================================
	// Expected results:
	// file log:                     displayed
	// console log:                  displayed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_CRITICAL);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);       // "test_componentA: debug"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);    // "test_componentA: debug"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_6)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:       debug
	// console_priority:                 debug
	// console_priority_by_component: critical
	// =======================================
	// Expected results:
	// file log:                     displayed
	// console log:                 suppressed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_DEBUG);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);       // "test_componentA: debug"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL); // "test_componentA: critical"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_CRITICAL);   // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_7)
{   
	// Preconditions:
	// file_priority:                 critical
	// file_priority_by_component:       debug
	// console_priority:                 debug
	// console_priority_by_component:    debug
	// =======================================
	// Expected results:
	// file log:                     displayed
	// console log:                  displayed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_CRITICAL, Poco::Message::Priority::PRIO_DEBUG);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);       // "test_componentA: debug"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);    // "test_componentA: debug"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_g_log_case_8)
{   
	// Preconditions:
	// file_priority:                    debug
	// file_priority_by_component:    critical
	// console_priority:              critical
	// console_priority_by_component: critical
	// =======================================
	// Expected results:
	// file log:                    suppressed
	// console log:                 suppressed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_DEBUG, Poco::Message::Priority::PRIO_CRITICAL);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL);    // "test_componentA: critical"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_CRITICAL); // "test_componentA: critical"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_CRITICAL,    // file_sev
			 		    Poco::Message::Priority::PRIO_CRITICAL);   // console_sev
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}


TEST_F(common_logger_test, component_overrides_g_log_case_f)
{   
	// Preconditions:
	// file_priority:                    debug
	// file_priority_by_component:       debug
	// console_priority:                 debug
	// console_priority_by_component:    debug
	// =======================================
	// Expected results:
	// file log:                     displayed
	// console log:                  displayed

	// set default file and console log levels
	set_log_level(Poco::Message::Priority::PRIO_DEBUG, Poco::Message::Priority::PRIO_DEBUG);

	// set component override vectors for the file and console
	std::vector<std::string> file_config_vector;
	std::vector<std::string> console_config_vector;
	file_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);       // "test_componentA: debug"
	console_config_vector.push_back(COMPONENTA_OVERRIDE_CONFIG_DEBUG);    // "test_componentA: debug"
	g_log->init_log_component_priorities(file_config_vector, LOG_FILE);
	g_log->init_log_component_priorities(console_config_vector, LOG_CONSOLE);

    // Simulate a LOG_DEBUG message coming from test_componentA
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, DEFAULT_MESSAGE);
	// These are the common_logger::log_check_component_priority() Parameters:
	g_log->log_check_component_priority(DEFAULT_MESSAGE,           // str: "This is a typical log message."
			 		    Poco::Message::Priority::PRIO_DEBUG,       // sev
			 		    Poco::Message::Priority::PRIO_DEBUG,       // file_sev
			 		    Poco::Message::Priority::PRIO_DEBUG);      // console_sev
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}


TEST_F(common_logger_test, component_overrides_log_sink_file)
{
	log_sink local_log_sink(FILENAME, TEST_COMPONENT_A);

	// set default log level to PRIO_INFORMATION for the file and console 
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);
	std::vector<std::string> config_vector;
	// set component override to debug in the config_vector list
	config_vector.push_back(COMPONENTA_FILE_OVERRIDE_CONFIG_DEBUG);
	g_log->init_log_component_priorities(config_vector, LOG_FILE);
	ASSERT_EQ(Poco::Message::Priority::PRIO_DEBUG,
		  g_log->get_component_priority(local_log_sink.tag(), LOG_FILE));

	// log_sink's log level should match override value
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_NOTICE));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_FATAL));
	ASSERT_FALSE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_TRACE));

	// Message should be emitted at override level, but not above that level
	// Call the API directly instead of via the macro since this
	// test uses a non-standard logger
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, 42,
				 DEFAULT_MESSAGE.c_str(), true, TEST_COMPONENT_A);
	local_log_sink.log(Poco::Message::Priority::PRIO_DEBUG, 42, "%s",
				DEFAULT_MESSAGE.c_str());
	local_log_sink.log(Poco::Message::Priority::PRIO_TRACE, 42, "%s",
				DEFAULT_MESSAGE.c_str());
	ASSERT_EQ(expected_message, m_file_out.str());
	ASSERT_EQ("", m_console_out.str());
}

TEST_F(common_logger_test, component_overrides_log_sink_console)
{
	log_sink local_log_sink(FILENAME, TEST_COMPONENT_A);

	// set default log level to PRIO_INFORMATION for the file and console 
	set_log_level(Poco::Message::Priority::PRIO_INFORMATION);
	std::vector<std::string> config_vector;
	// set component override to debug in the config_vector list
	config_vector.push_back(COMPONENTA_FILE_OVERRIDE_CONFIG_DEBUG);
	g_log->init_log_component_priorities(config_vector, LOG_CONSOLE);
	ASSERT_EQ(Poco::Message::Priority::PRIO_DEBUG,
		  g_log->get_component_priority(local_log_sink.tag(), LOG_CONSOLE));

	// log_sink's log level should match override value
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_DEBUG));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_INFORMATION));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_NOTICE));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_WARNING));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_ERROR));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_CRITICAL));
	ASSERT_TRUE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_FATAL));
	ASSERT_FALSE(local_log_sink.is_enabled(Poco::Message::Priority::PRIO_TRACE));

	// Message should be emitted at override level, but not above that level
	// Call the API directly instead of via the macro since this
	// test uses a non-standard logger
	const std::string expected_message =
		generateMessage(Poco::Message::Priority::PRIO_DEBUG, 42,
				 DEFAULT_MESSAGE.c_str(), true, TEST_COMPONENT_A);
	local_log_sink.log(Poco::Message::Priority::PRIO_DEBUG, 42, "%s",
				DEFAULT_MESSAGE.c_str());
	local_log_sink.log(Poco::Message::Priority::PRIO_TRACE, 42, "%s",
				DEFAULT_MESSAGE.c_str());
	ASSERT_EQ("", m_file_out.str());
	ASSERT_EQ(expected_message, m_console_out.str());
}
