/**
 * @file
 *
 * Implementation of the common logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "common_logger.h"
#include <Poco/Logger.h>
#include <Poco/Path.h>

/* global */ std::unique_ptr<common_logger> g_log;

namespace
{

/**
 * Do-nothing realization of the log_observer interface.
 */
class null_log_observer : public common_logger::log_observer
{
public:
	void notify(Poco::Message::Priority priority) override
	{ }
};

} // end namespace

common_logger::common_logger(Poco::Logger* const file_log,
                             Poco::Logger* const console_log):
	m_file_log(file_log),
	m_console_log(console_log),
	m_observer(std::make_shared<null_log_observer>())
{ }

void common_logger::log(const std::string& str, const Poco::Message::Priority sev)
{
	Poco::Message m("common_logger", str, sev);

	m_file_log->log(m);

	if(m_console_log != NULL)
	{
		m_console_log->log(m);
	}

	m_observer->notify(sev);
}

void common_logger::set_observer(log_observer::ptr observer)
{
	if(observer != nullptr)
	{
		m_observer = observer;
	}
	else
	{
		m_observer = std::make_shared<null_log_observer>();
	}
}

void common_logger::trace(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_TRACE);
}

void common_logger::debug(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_DEBUG);
}

void common_logger::information(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_INFORMATION);
}

void common_logger::notice(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_NOTICE);
}

void common_logger::warning(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_WARNING);
}

void common_logger::error(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_ERROR);
}

void common_logger::critical(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_CRITICAL);
}

void common_logger::fatal(const std::string& str)
{
	log(str, Poco::Message::Priority::PRIO_FATAL);
}

void common_logger::sinsp_logger_callback(std::string&& str,
                                          const sinsp_logger::severity sev)
{
	if(g_log == nullptr)
	{
		return;
	}

	switch(sev)
	{
	case sinsp_logger::SEV_FATAL:
		g_log->fatal(str);
		break;

	case sinsp_logger::SEV_CRITICAL:
		g_log->critical(str);
		break;

	case sinsp_logger::SEV_ERROR:
		g_log->error(str);
		break;

	case sinsp_logger::SEV_WARNING:
		g_log->warning(str);
		break;

	case sinsp_logger::SEV_NOTICE:
		g_log->notice(str);
		break;

	case sinsp_logger::SEV_INFO:
		g_log->information(str);
		break;

	case sinsp_logger::SEV_DEBUG:
		g_log->debug(str);
		break;

	case sinsp_logger::SEV_TRACE:
		g_log->trace(str);
		break;
	}
}

bool common_logger::is_enabled(const Poco::Message::Priority severity) const
{
	return (((m_file_log != nullptr) && (m_file_log->getLevel() >= severity)) ||
	        ((m_console_log != nullptr) && (m_console_log->getLevel() >= severity)));
}

log_sink::log_sink(const std::string& file,
                   const std::string& component) :
	m_tag(component +
	      (component.empty() ? "" : ":") +
	      Poco::Path(file).getBaseName())
{
}

/**
 * Attempts to write the log message described by the given line number, format
 * specifier, and variable argument list to the given log_string.  If the given
 * log_string's capacity is sufficient to hold the fully-formatted log message,
 * then this function will write the log message to it.  If the given 
 * log_string's capacity is not sufficient to hold the fully-formatted log
 * message, then its value on return is undefined; clients should use log_string
 * only if the return value of this function is less than or equal to the
 * capacity of the given log_string.
 *
 * @returns the total buffer size necessary to hold the fully-formatted log
 *          message.
 */
std::string::size_type log_sink::generate_log(std::vector<char>& log_buffer,
                                              const int line,
                                              const char* const fmt,
                                              va_list& args) const
{
	va_list mutable_args;

	va_copy(mutable_args, args);

	std::string::size_type prefix_length = 0;

	if(line)
	{
		// Try to write the prefix to log_buffer
		prefix_length = std::snprintf(&log_buffer[0],
		                              log_buffer.capacity(),
		                              "%s:%d: ",
		                              m_tag.c_str(),
		                              line);
	}

	char *suffix_target = nullptr;
	std::string::size_type suffix_buffer_size = 0;
	if(prefix_length < log_buffer.capacity())
	{
		suffix_target = &log_buffer[prefix_length];
		suffix_buffer_size = log_buffer.capacity() - prefix_length;
	}

	const std::string::size_type suffix_length =
		std::vsnprintf(suffix_target,
		               suffix_buffer_size,
		               fmt,
		               mutable_args);

	// One extra byte needed for the NUL terminator
	const std::string::size_type total_length = prefix_length + suffix_length + 1;

	return total_length;
}

std::string log_sink::build(const int line, const char* const fmt, va_list& args) const
{
	// Allocate a string with an initial capacity of DEFAULT_LOG_STR_LENGTH.
	// The hope is that most log messages will fit into a buffer of this
	// size.
	std::vector<char> log_buffer(DEFAULT_LOG_STR_LENGTH, '\0');

	const std::string::size_type log_length =
		generate_log(log_buffer, line, fmt, args);

	// If the actual log length exceeds DEFAULT_LOG_STR_LENGTH, then
	// the previous call to generate_log was unable to write the fully-
	// formatted log message to log_buffer.  Resize log_buffer to accomodate
	// the full size of the log line and retry the log generation.
	if(log_length > DEFAULT_LOG_STR_LENGTH)
	{
		log_buffer.resize(log_length);
		static_cast<void>(generate_log(log_buffer, line, fmt, args));
	}

	return std::string(&log_buffer[0]);
}

std::string log_sink::build(const char *const fmt, ...) const
{
	va_list args;

	va_start(args, fmt);
	std::string message = build(0 /*suffix only*/, fmt, args);
	va_end(args);
	return message;
}

void log_sink::log(const Poco::Message::Priority severity,
                   const int line,
                   const char* const fmt,
                   ...) const
{
	va_list args;

	va_start(args, fmt);
	std::string message = build(line, fmt, args);
	va_end(args);

	g_log->log(message, severity);
}

void log_sink::log(const Poco::Message::Priority severity,
                   const int line,
                   const std::string& str) const
{
	log(severity, line, "%s", str.c_str());
}
