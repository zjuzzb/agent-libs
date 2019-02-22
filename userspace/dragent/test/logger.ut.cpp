#include <gtest.h>
#include "dragent/src/logger.h" /* full path because multiple files have this name*/
#include "watchdog_runnable_fatal_error.h"

namespace
{

const std::string FILENAME = "test_filename.cpp";
const std::string STRIPPED_FILENAME = "test_filename";
const std::string DEFAULT_COMPONENT = "test:dragent";
const std::string DEFAULT_MESSAGE = "This is a typical log message.";

#if _DEBUG
const bool EMIT_DEBUG_LOG = true;
#else
const bool EMIT_DEBUG_LOG = false;
#endif

/**
 * Generate a sample log line with the given priority, line number, and
 * log message.  This should format things like log_sink::stream_log_output
 */
std::string generateMessage(const int priority,
                            const int line,
                            const std::string& message = DEFAULT_MESSAGE,
                            const bool emitLog = true,
			    const std::string& component = DEFAULT_COMPONENT)
{
	std::string log;

	if(emitLog)
	{
		const std::string opt_separator = (component.empty() ? "" : ":");

		// 8, test:dragent:test_filename:29: hello, world\n
		log =        std::to_string(priority) +
		       ", " + component + opt_separator +
		              STRIPPED_FILENAME +
		       ":"  + std::to_string(line) +
		       ": " + message +
		       "\n";
	}

	return log;
}

class logger_test : public testing::Test
{
public:
	logger_test() :
		m_out(),
		s_log_sink(m_out, FILENAME, DEFAULT_COMPONENT)
	{
	}

	virtual void TearDown() override
	{
		m_out.str("");
		m_out.clear();
	}

	std::stringstream m_out;

	// This is named 's_log_sink' even though the object isn't static.
	// The rationale for this is that the logging API expects there to
	// be a global static with that name.  In the context of the unit
	// test, we don't want that global static.  Instead, we define it
	// here with the expected name.
	log_sink s_log_sink;
};

} // end namespace

TEST_F(logger_test, trace)
{
	// Note for this and other tests in this file, it is important to keep
	// the line number recording and the call to the logging API on the
	// same line.
	const int line = __LINE__; LOG_TRACE("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_TRACE, line),
	          m_out.str());
}

TEST_F(logger_test, debug)
{
	const int line = __LINE__; LOG_DEBUG("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_DEBUG, line),
	          m_out.str());
}

TEST_F(logger_test, info)
{
	const int line = __LINE__; LOG_INFO("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_INFORMATION, line),
	          m_out.str());
}

TEST_F(logger_test, notice)
{
	const int line = __LINE__; LOG_NOTICE("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_NOTICE, line),
	          m_out.str());
}

TEST_F(logger_test, warning)
{
	const int line = __LINE__; LOG_WARNING("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_WARNING, line),
	          m_out.str());
}

TEST_F(logger_test, error)
{
	const int line = __LINE__; LOG_ERROR("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_ERROR, line),
	          m_out.str());
}

TEST_F(logger_test, critical)
{
	const int line = __LINE__; LOG_CRITICAL("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_CRITICAL, line),
	          m_out.str());
}

TEST_F(logger_test, fatal)
{
	const int line = __LINE__; LOG_FATAL("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_FATAL, line),
	          m_out.str());
}

/**
 * A test that will force the logging API to reallocate a larger buffer.
 */
TEST_F(logger_test, larger_than_deafult_max)
{
	const std::string message(2 * log_sink::DEFAULT_LOG_STR_LENGTH, 'a');
	const int line = __LINE__; LOG_FATAL("%s", message.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_FATAL, line, message),
	          m_out.str());
}

/**
 * Ensure that if we pass a string that contains printf-style placeholders
 * without any additional arguments, that the std::string version of log()
 * gets called, and that the log contains the literal placeholders (i.e.,
 * nothing along the way tries to fill those placeholders, reading random
 * data off the stack.
 */
TEST_F(logger_test, string_with_placeholders_no_values)
{
	const std::string message = "This %s is %d a %f test %zu";
	const int line = __LINE__; LOG_FATAL(message);

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_FATAL, line, message),
	          m_out.str());
}

TEST_F(logger_test, empty_component_name_no_colon)
{
	const std::string component = "";
	const int priority = Poco::Message::Priority::PRIO_FATAL;
	const bool emitLog = true;
	const int line = 42; // Some example line number, value is not important
	log_sink local_log_sink(m_out, FILENAME, component);

	// Call the API directly instead of via the macro since this
	// test uses a non-standard logger
	local_log_sink.log(priority, line, "%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(priority,
	                          line,
	                          DEFAULT_MESSAGE,
	                          emitLog,
	                          component),
	          m_out.str());
}

TEST_F(logger_test, dbg_trace)
{
	const int line = __LINE__; DBG_LOG_TRACE("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_TRACE,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_debug)
{
	const int line = __LINE__; DBG_LOG_DEBUG("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_DEBUG,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_info)
{
	const int line = __LINE__; DBG_LOG_INFO("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_INFORMATION,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_notice)
{
	const int line = __LINE__; DBG_LOG_NOTICE("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_NOTICE,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_warning)
{
	const int line = __LINE__; DBG_LOG_WARNING("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_WARNING,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_error)
{
	const int line = __LINE__; DBG_LOG_ERROR("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_ERROR,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_critical)
{
	const int line = __LINE__; DBG_LOG_CRITICAL("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_CRITICAL,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}

TEST_F(logger_test, dbg_fatal)
{
	const int line = __LINE__; DBG_LOG_FATAL("%s", DEFAULT_MESSAGE.c_str());

	ASSERT_EQ(generateMessage(Poco::Message::Priority::PRIO_FATAL,
	                          line,
	                          DEFAULT_MESSAGE,
	                          EMIT_DEBUG_LOG),
	          m_out.str());
}
