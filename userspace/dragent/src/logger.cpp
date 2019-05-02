#include "logger.h"
#include "configuration.h"
#include "user_event_logger.h"
#include <sys/statvfs.h>

using namespace Poco;
using Poco::Message;

unique_ptr<dragent_logger> g_log;

dragent_logger::dragent_logger(Logger* file_log, Logger* console_log):
	m_file_log(file_log),
	m_console_log(console_log),
	m_internal_metrics()
{ }

void dragent_logger::log(const std::string& str, uint32_t sev)
{
	Message m("dragent_logger", str, (Message::Priority) sev);
	m_file_log->log(m);
	if(m_console_log != NULL)
	{
		m_console_log->log(m);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify((Message::Priority) sev);
	}
}

void dragent_logger::trace(const std::string& str)
{
	m_file_log->trace(str);
	if(m_console_log != NULL)
	{
		m_console_log->trace(str);
	}
}

void dragent_logger::debug(const std::string& str)
{
	m_file_log->debug(str);
	if(m_console_log != NULL)
	{
		m_console_log->debug(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_DEBUG);
	}
}

void dragent_logger::information(const std::string& str)
{
	m_file_log->information(str);
	if(m_console_log != NULL)
	{
		m_console_log->information(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_INFORMATION);
	}
}

void dragent_logger::notice(const std::string& str)
{
	m_file_log->notice(str);
	if(m_console_log != NULL)
	{
		m_console_log->notice(str);
	}
}

void dragent_logger::warning(const std::string& str)
{
	m_file_log->warning(str);
	if(m_console_log != NULL)
	{
		m_console_log->warning(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_WARNING);
	}
}

void dragent_logger::error(const std::string& str)
{
	m_file_log->error(str);
	if(m_console_log != NULL)
	{
		m_console_log->error(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_ERROR);
	}
}

void dragent_logger::critical(const std::string& str)
{
	m_file_log->critical(str);
	if(m_console_log != NULL)
	{
		m_console_log->critical(str);
	}
}

void dragent_logger::fatal(const std::string& str)
{
	m_file_log->fatal(str);
	if(m_console_log != NULL)
	{
		m_console_log->fatal(str);
	}
}

void dragent_logger::trace(std::string&& str)
{
	m_file_log->trace(str);
	if(m_console_log != NULL)
	{
		m_console_log->trace(str);
	}
}

void dragent_logger::debug(std::string&& str)
{
	m_file_log->debug(str);
	if(m_console_log != NULL)
	{
		m_console_log->debug(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_DEBUG);
	}
}

void dragent_logger::information(std::string&& str)
{
	m_file_log->information(str);
	if(m_console_log != NULL)
	{
		m_console_log->information(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_INFORMATION);
	}
}

void dragent_logger::notice(std::string&& str)
{
	m_file_log->notice(str);
	if(m_console_log != NULL)
	{
		m_console_log->notice(str);
	}
}

void dragent_logger::warning(std::string&& str)
{
	m_file_log->warning(str);
	if(m_console_log != NULL)
	{
		m_console_log->warning(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_WARNING);
	}
}

void dragent_logger::error(std::string&& str)
{
	m_file_log->error(str);
	if(m_console_log != NULL)
	{
		m_console_log->error(str);
	}
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_ERROR);
	}
}

void dragent_logger::critical(std::string&& str)
{
	m_file_log->critical(str);
	if(m_console_log != NULL)
	{
		m_console_log->critical(str);
	}
}

void dragent_logger::fatal(std::string&& str)
{
	m_file_log->fatal(str);
	if(m_console_log != NULL)
	{
		m_console_log->fatal(str);
	}
}

void dragent_logger::sinsp_logger_callback(std::string&& str,
                                           const sinsp_logger::severity sev)
{
	ASSERT(g_log != NULL);

	switch(sev)
	{
	case sinsp_logger::SEV_FATAL:
		g_log->fatal(std::move(str));
		break;

	case sinsp_logger::SEV_CRITICAL:
		g_log->critical(std::move(str));
		break;

	case sinsp_logger::SEV_ERROR:
		g_log->error(std::move(str));
		break;

	case sinsp_logger::SEV_WARNING:
		g_log->warning(std::move(str));
		break;

	case sinsp_logger::SEV_NOTICE:
		g_log->notice(std::move(str));
		break;

	case sinsp_logger::SEV_INFO:
		g_log->information(std::move(str));
		break;

	case sinsp_logger::SEV_DEBUG:
		g_log->debug(std::move(str));
		break;

	case sinsp_logger::SEV_TRACE:
		g_log->trace(std::move(str));
		break;

	default:
		ASSERT(false);
	}
}

avoid_block_channel::avoid_block_channel(const AutoPtr<Poco::FileChannel>& file_channel, const std::string& machine_id):
	m_file_channel(file_channel),
	m_machine_id(machine_id),
	m_error_event_sent(false)
{
}

void avoid_block_channel::log(const Message &message)
{
	try
	{
		m_file_channel->log(message);
		m_error_event_sent = false;
	}
	catch (const Poco::WriteFileException& ex)
	{
		cerr << "Cannot write to draios.log" << endl;
		if(g_log && !m_error_event_sent)
		{
			// set immediately to prevent many threads racing in here
			m_error_event_sent = true;
			std::string fname = m_file_channel->getProperty("path");
			struct statvfs buf;
			if(0 == statvfs(fname.c_str(), &buf))
			{
				std::ostringstream os;
				os << "Logger (" << fname << "): [" << ex.displayText() << ']' << std::endl <<
					"disk free=" << buf.f_bsize * buf.f_bfree / 1024 << " kb";
				std::unordered_map<std::string, std::string> tags{{"source", "dragent"}};

				user_event_logger::log(
						sinsp_user_event::to_string(
							get_epoch_utc_seconds_now(),
							"DragentLoggerError",
							os.str(),
							event_scope("host.mac", m_machine_id),
							move(tags)),
						user_event_logger::SEV_EVT_ERROR);
			}
		}
	}
}

void avoid_block_channel::open()
{
	m_file_channel->open();
}

void avoid_block_channel::close()
{
	m_file_channel->close();
}

void log_sink::dragent_log_output::log(const std::string& message, int severity)
{
	g_log->log(message, severity);
}

log_sink::stream_log_output::stream_log_output(std::ostream& out) :
	m_out(out)
{
}

void log_sink::stream_log_output::log(const std::string& message, int severity)
{
	// Since this is used only for unit testint, there's no real value in
	// translating the severity to a string
	m_out << severity << ", " << message << std::endl;
}

log_sink::log_sink(log_output* output,
                   const std::string& file,
                   const std::string& component) :
	m_log_output(output),
	m_tag(component +
	      (component.empty() ? "" : ":") +
	      Poco::Path(file).getBaseName())
{
}

log_sink::log_sink(const std::string& file, const std::string& component) :
	log_sink(new dragent_log_output(), file, component)
{
}

log_sink::log_sink(std::ostream& out,
                   const std::string& file,
                   const std::string& component) :
	log_sink(new stream_log_output(out), file, component)
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
		prefix_length = std::snprintf(& log_buffer[0],
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

void log_sink::log(const uint32_t severity, const int line, const char* const fmt, ...) const
{
	va_list args;

	va_start(args, fmt);
	std::string message = build(line, fmt, args);
	va_end(args);

	m_log_output->log(message, severity);
}

void log_sink::log(uint32_t severity, int line, const std::string& str) const
{
	log(severity, line, "%s", str.c_str());
}
