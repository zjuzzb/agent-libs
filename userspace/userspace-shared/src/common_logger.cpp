/**
 * @file
 *
 * Implementation of the common logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "common_logger.h"
#include "thread_utils.h"
#include "thread_safe_container/blocking_queue.h"
#include <Poco/Logger.h>
#include <Poco/Path.h>

/* global */ std::unique_ptr<common_logger> g_log;

COMMON_LOGGER();

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

using priority_map_t = std::map<std::string, Poco::Message::Priority>;
static priority_map_t s_priority_map = {
	{ "fatal",      Poco::Message::Priority::PRIO_FATAL},
	{ "critical",   Poco::Message::Priority::PRIO_CRITICAL},
	{ "error",      Poco::Message::Priority::PRIO_ERROR},
	{ "warning",    Poco::Message::Priority::PRIO_WARNING},
	{ "notice",     Poco::Message::Priority::PRIO_NOTICE},
	{ "info",       Poco::Message::Priority::PRIO_INFORMATION},
	{ "debug",      Poco::Message::Priority::PRIO_DEBUG},
	{ "trace",      Poco::Message::Priority::PRIO_TRACE},
};

common_logger::common_logger(Poco::Logger* const file_log,
			     Poco::Logger* const console_log):
	m_file_log(file_log),
	m_console_log(console_log),
	m_file_log_priority((Poco::Message::Priority)-1),
	m_console_log_priority((Poco::Message::Priority)-1),
	m_observer(std::make_shared<null_log_observer>())
{ }

common_logger::common_logger(Poco::Logger* const file_log,
			     Poco::Logger* const console_log,
			     Poco::Message::Priority const file_sev,
			     Poco::Message::Priority const console_sev,
			     const std::vector<std::string>& file_config_vector,
			     const std::vector<std::string>& console_config_vector) :
	m_file_log(file_log),
	m_console_log(console_log),
	m_file_log_priority(file_sev),
	m_console_log_priority(console_sev),
	m_observer(std::make_shared<null_log_observer>())
{
	init_log_component_priorities(file_config_vector, log_destination::LOG_FILE);
	init_log_component_priorities(console_config_vector, log_destination::LOG_CONSOLE);
}

void common_logger::init_log_component_priorities(const std::vector<std::string>& config_vector, const log_destination log_dest)
{
	const std::string delimiter = ": ";
	for (auto component_level : config_vector)
	{
		std::string component;
		std::string sev_string;
		size_t pos = component_level.find(delimiter);
		if (pos != std::string::npos)
		{
			component = component_level.substr(0, pos);
			sev_string = component_level.substr(pos + delimiter.length(),
							component_level.length());
			if (s_priority_map.count(sev_string) > 0)
			{
				if (log_dest == log_destination::LOG_FILE)
				{
				    m_file_log_component_priorities[component] = s_priority_map[sev_string];
				}
				else if (log_dest == log_destination::LOG_CONSOLE)
				{
				    m_console_log_component_priorities[component] = s_priority_map[sev_string];
				}
			}
			else
			{
				// Ironically, can't use LOG_ macro here since g_log isn't constructed yet
				log("common_logger: Unknown priority=" + sev_string + " in config=" +
				    component_level, Poco::Message::Priority::PRIO_NOTICE);
			}
		}
		else
		{
			// can't use LOG_ macro here since g_log isn't constructed yet
			log("common_logger: Unparseable string=" + component_level,
			    Poco::Message::Priority::PRIO_NOTICE);
		}
	}
}

/**
 * log_check_component_priority is where the decision is made to log or not to log
 * the message to the destination output device.
 */
void common_logger::log_check_component_priority(const std::string& str,
						 const Poco::Message::Priority sev,
						 const Poco::Message::Priority file_sev,
						 const Poco::Message::Priority console_sev)
{
	Poco::Message m("common_logger", str, sev);

	m.setTid(thread_utils::get_tid());

	if (file_sev >= sev)
	{
		m_file_log->log(m);
	}

	if(console_sev >= sev)
	{
		m_console_log->log(m);
	}

	m_observer->notify(sev);
}

void common_logger::log(const std::string& str, const Poco::Message::Priority sev)
{
	if (is_enabled(sev))
	{
		log_check_component_priority(str, sev, m_file_log_priority, m_console_log_priority);
	}
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

// This common_logger::is_enabled single parameter version is used internally by common_logger::log
// Here severity is the priority of the log message.  It is called first, to
// determine if logging should be done for the message based on its severity,
// and returns TRUE, meaning more processing should be done on the message, 
// or FALSE, meaning we are finished with this message. 
bool common_logger::is_enabled(const Poco::Message::Priority severity) const
{
	return (((m_file_log != nullptr) && (m_file_log_priority >= severity)) ||
		((m_console_log != nullptr) && (m_console_log_priority >= severity)));
}

// Here severity is the priority of the log message,
// and component_file_priority is the value specified in the dragent.yaml config.
bool common_logger::is_enabled(const Poco::Message::Priority severity,
			       const Poco::Message::Priority component_file_priority,
			       const Poco::Message::Priority component_console_priority) const
{
	return (((m_file_log != nullptr) && (component_file_priority >= severity)) ||
		((m_console_log != nullptr) && (component_console_priority >= severity)));
}

// Based on parameter log_dest, search for parameter component in either the 
// m_file_log_component_priorities or m_file_log_component_priorities_list (these
// lists were constructed using file_config_vector and console_config_vector).  
// If the component is found, return the list priority value; otherwise return
// either the m_file_log_priority (that was constructed using file_sev), or
// return the m_console_log_priority (that was constructed using console_sev).
Poco::Message::Priority common_logger::get_component_priority(const std::string& component,
                                                              const log_destination log_dest) const
{
	if (log_dest == log_destination::LOG_FILE)
	{
		std::unordered_map<std::string, Poco::Message::Priority>::const_iterator it =
			m_file_log_component_priorities.find(component);
		if (it != m_file_log_component_priorities.end())
		{
			return it->second;
		}
		else
		{
			return m_file_log_priority;
		}
	}
	else
	{
		std::unordered_map<std::string, Poco::Message::Priority>::const_iterator it =
			m_console_log_component_priorities.find(component);
		if (it != m_console_log_component_priorities.end())
		{
			return it->second;
		}
		else
		{
			return m_console_log_priority;
		}
	}
}

log_sink::log_sink(const std::string& file,
                   const std::string& component) :
	m_tag(component +
	      (component.empty() ? "" : ":") +
	      Poco::Path(file).getBaseName()),
	m_component_file_priority(static_cast<Poco::Message::Priority>(-1)),
	m_component_console_priority(static_cast<Poco::Message::Priority>(-1))
{
}

/**
 * Checks if log message should be emitted at input severity level.
 * Component level overrides are enforced.
 */
bool log_sink::is_enabled(const Poco::Message::Priority severity) const
{
	if (!g_log)
	{
		// If we haven't initialized the global logger (yet),
		// we want messages to make it all the way to the cache
		return true;
	}

	if (m_component_file_priority == static_cast<Poco::Message::Priority>(-1))
	{
		// Use get_component_priority to search the m_file_log_component_priorities list.
		m_component_file_priority = g_log->get_component_priority(tag(), log_destination::LOG_FILE);
	}
	if (m_component_console_priority == static_cast<Poco::Message::Priority>(-1))
	{
		// Use get_component_priority to search the m_console_log_component_priorities list.
		m_component_console_priority = g_log->get_component_priority(tag(), log_destination::LOG_CONSOLE);
	}
	// now use the common_logger::is_enabled
	return g_log->is_enabled(severity, m_component_file_priority, m_component_console_priority);
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

	va_end(mutable_args);

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
	if (nullptr == g_log)
	{	
		// Logger isn't initialized. Build the message and save it
		// so we can log it later.
		va_list args;
		va_start(args, fmt);
		std::string message = build(line, fmt, args);
		va_end(args);
		common_logger_cache::save(m_tag, message, severity);

	}
	else if (is_enabled(severity)) 
	{
		va_list args;
		va_start(args, fmt);
		std::string message = build(line, fmt, args);
		va_end(args);
		g_log->log_check_component_priority(message, severity, m_component_file_priority, m_component_console_priority);
	}
}

void log_sink::log(const Poco::Message::Priority severity,
                   const int line,
                   const std::string& str) const
{
	log(severity, line, "%s", str.c_str());
}

namespace common_logger_cache
{

namespace {

struct cached_message {
	const std::string *component_tag;
	std::string message;
	Poco::Message::Priority sev;
}; 

using cache_t = thread_safe_container::blocking_queue<cached_message>;
const unsigned MAX_MESSAGES = 1000; 

cache_t& get_cache() {
	// This is kept inside a function so that clients don't need
	// to worry about static initialization order. This will get
	// initialized on first call.
	static cache_t cache(MAX_MESSAGES);
	return cache;
}

} // namespace

void save(const std::string &component_tag,
	  const std::string &str,
	  Poco::Message::Priority sev)
{
	cached_message message = { &component_tag, str, sev };
	get_cache().put(message);
}

// log_and_purge is called by processes dragent, agentone and agentino after initialization
// of logging and the initial LOG_ message is generated.
void log_and_purge()
{
	if (nullptr == g_log) 
	{
		return;
	}

	if (get_cache().size() >= MAX_MESSAGES)
	{
		g_log->warning("The common logger cache reached max capacity.");
	}

	cached_message data;

	while (get_cache().get(&data, 1000 /*one second timeout*/))
	{
		auto file_component_priority = g_log->get_component_priority(*data.component_tag, log_destination::LOG_FILE);
		auto console_component_priority = g_log->get_component_priority(*data.component_tag, log_destination::LOG_CONSOLE);
		g_log->log_check_component_priority(data.message, data.sev, file_component_priority, console_component_priority);
	}
}

}


