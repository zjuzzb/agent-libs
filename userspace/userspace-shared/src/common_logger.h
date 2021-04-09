/**
 * @file
 *
 * Interface to common_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "logger.h"

#include <Poco/Message.h>

#include <assert.h>
#include <atomic>
#include <exception>
#include <memory>
#include <stdarg.h>
#include <string>
#include <vector>
#include <unordered_map>

// define the logger destinations
enum  log_destination { LOG_FILE, LOG_CONSOLE };
namespace Poco
{
class Logger;
}

class common_logger
{
public:
	/**
	 * Interface to an object that can be notified when a log of a given
	 * priority is generated.
	 */
	class log_observer
	{
	public:
		using ptr = std::shared_ptr<log_observer>;

		virtual ~log_observer() = default;
		virtual void notify(Poco::Message::Priority priority) = 0;
	};

	/**
	 * Use this constructor if you don't care about file logger and are
	 * passing in a null channel. It is mostly used by unit tests.
	 */
	common_logger(Poco::Logger* file_log, Poco::Logger* console_log);
	/**
	 * Use this constructor if you care about file and console logging.
	 * Applications like dragent and agentone do.
	 */
	common_logger(Poco::Logger* file_log,
		      Poco::Logger* console_log,
		      Poco::Message::Priority file_sev,
		      Poco::Message::Priority console_sev,
		      const std::vector<std::string>& file_config_vector,
		      const std::vector<std::string>& console_config_vector);
	/**
	 * Set the observer that will get notified of logs that get written.
	 */
	void set_observer(log_observer::ptr observer);

	/**
	 * Log method with default file level check
	 */
	void log(const std::string& str, Poco::Message::Priority sev);
	/**
	 * Log method that checks file level (used for implementing component
	 * level overrides).
	 */
	void log_check_component_priority(const std::string& str,
					  const Poco::Message::Priority sev,
					  const Poco::Message::Priority file_sev,
					  const Poco::Message::Priority console_sev);
	void trace(const std::string& str);
	void debug(const std::string& str);
	void information(const std::string& str);
	void notice(const std::string& str);
	void warning(const std::string& str);
	void error(const std::string& str);
	void critical(const std::string& str);
	void fatal(const std::string& str);

	static void sinsp_logger_callback(std::string&& str, sinsp_logger::severity sev);

	bool is_enabled(Poco::Message::Priority severity) const;
	bool is_enabled(const Poco::Message::Priority severity,
			const Poco::Message::Priority component_file_priority,
			const Poco::Message::Priority component_console_priority) const;
	void init_log_component_priorities(const std::vector<std::string>& config_vector, const log_destination log_dest);
	Poco::Message::Priority get_component_priority(const std::string& component, const log_destination log_dest) const;
#ifdef SYSDIG_TEST
	void set_file_log_priority(const Poco::Message::Priority severity)
	{
		m_file_log_priority = severity;
	}
	void set_console_log_priority(const Poco::Message::Priority severity)
	{
		m_console_log_priority = severity;
	}
#endif

private:
	// The order of declaration and initialization here must match the common_logger constructor
	Poco::Logger* const m_file_log;
	Poco::Logger* const m_console_log;
#ifdef SYSDIG_TEST
	Poco::Message::Priority mutable m_file_log_priority;
#else
	Poco::Message::Priority const m_file_log_priority;
#endif

#ifdef SYSDIG_TEST
	Poco::Message::Priority mutable m_console_log_priority;
#else
	Poco::Message::Priority const m_console_log_priority;
#endif
	// m_file_log_component_priorities (and m_file_log_component_priorities) are mutable because
	// they are populated after parsing a std::vector<std::string> that is sent to the constructor
	// from the config.
	// If the conversion is done outside the constructor and the fully built unordered_map
	// is passed into the constructor, we can make it const
	// Probably not worth the trouble since each application calls the constructor separately
	// and unit test code also modifies it.
	std::unordered_map<std::string, Poco::Message::Priority> mutable m_file_log_component_priorities;
	std::unordered_map<std::string, Poco::Message::Priority> mutable m_console_log_component_priorities;
	std::shared_ptr<log_observer> m_observer;
};

/**
 * Functions used to manipulate cache that saves message before 
 * the common logger is initialized. 
 */
namespace common_logger_cache
{
/**
 * Save a message into a static buffer. This is meant to be used
 * by the log_sink if something attempt to log a message before 
 * the logger is initialized. 
 */
void save(const std::string &component_tag, 
	  const std::string &str, 
	  Poco::Message::Priority sev);

/**
 * Log all of the messages that are saved in the cache.
 */
void log_and_purge();
};

/**
 * Meant to be used inside a cpp file to provide logs targeted
 * to that compilation unit. Do not use this class. Use the
 * COMMON_LOGGER and LOG_XYZ macros.
 */
class log_sink
{
public:
	const static size_t DEFAULT_LOG_STR_LENGTH = 256;

	log_sink(const std::string& file, const std::string& component);

	void log(Poco::Message::Priority severity, int line, const char* fmt, ...) const
	    __attribute__((format(printf, 4, 5)));
	void log(Poco::Message::Priority severity, int line, const std::string& str) const;
	std::string build(const char* fmt, ...) const;
	const std::string& tag() const { return m_tag; };
	bool is_enabled(Poco::Message::Priority severity) const;

private:
	std::string::size_type generate_log(std::vector<char>& log_buffer,
	                                    int line,
	                                    const char* fmt,
	                                    va_list& args) const;
	std::string build(int line, const char* fmt, va_list& args) const;

	// [<optional component>:]<filename without extension>
	const std::string m_tag;
	// File log level and console level overrides associated with component,
	// extracted from g_log and cached here for performance optimization.
	mutable Poco::Message::Priority m_component_file_priority;
	mutable Poco::Message::Priority m_component_console_priority;
};

extern std::unique_ptr<common_logger> g_log;

// Make an instance of a logger in a component that will always print
// the filename and the line number. If prefix is provided then that will
// proceed the filename.
#define COMMON_LOGGER(__optional_prefix) \
	static const log_sink s_log_sink(__FILE__, "" __optional_prefix)

#define LOG_AT_PRIO_(priority, ...)                                                              \
	do                                                                                       \
	{                                                                                        \
		s_log_sink.log((priority), __LINE__, __VA_ARGS__);                               \
	} while (false)

#define LOG_WILL_EMIT(priority) (s_log_sink.is_enabled(priority))

// clang-format off
// Macros to use in the cpp file to interface with the component logger.
#define LOG_TRACE(...)    LOG_AT_PRIO_(Poco::Message::Priority::PRIO_TRACE,       __VA_ARGS__)
#define LOG_DEBUG(...)    LOG_AT_PRIO_(Poco::Message::Priority::PRIO_DEBUG,       __VA_ARGS__)
#define LOG_INFO(...)     LOG_AT_PRIO_(Poco::Message::Priority::PRIO_INFORMATION, __VA_ARGS__)
#define LOG_NOTICE(...)   LOG_AT_PRIO_(Poco::Message::Priority::PRIO_NOTICE,      __VA_ARGS__)
#define LOG_WARNING(...)  LOG_AT_PRIO_(Poco::Message::Priority::PRIO_WARNING,     __VA_ARGS__)
#define LOG_ERROR(...)    LOG_AT_PRIO_(Poco::Message::Priority::PRIO_ERROR,       __VA_ARGS__)
#define LOG_CRITICAL(...) LOG_AT_PRIO_(Poco::Message::Priority::PRIO_CRITICAL,    __VA_ARGS__)
#define LOG_FATAL(...)    LOG_AT_PRIO_(Poco::Message::Priority::PRIO_FATAL,       __VA_ARGS__)

#if _DEBUG
#    define DBG_LOG_TRACE(...)    LOG_TRACE(__VA_ARGS__)
#    define DBG_LOG_DEBUG(...)    LOG_DEBUG(__VA_ARGS__)
#    define DBG_LOG_INFO(...)     LOG_INFO(__VA_ARGS__)
#    define DBG_LOG_NOTICE(...)   LOG_NOTICE(__VA_ARGS__)
#    define DBG_LOG_WARNING(...)  LOG_WARNING(__VA_ARGS__)
#    define DBG_LOG_ERROR(...)    LOG_ERROR(__VA_ARGS__)
#    define DBG_LOG_CRITICAL(...) LOG_CRITICAL(__VA_ARGS__)
#    define DBG_LOG_FATAL(...)    LOG_FATAL(__VA_ARGS__)
#else
#    define DBG_LOG_TRACE(...)
#    define DBG_LOG_DEBUG(...)
#    define DBG_LOG_INFO(...)
#    define DBG_LOG_NOTICE(...)
#    define DBG_LOG_WARNING(...)
#    define DBG_LOG_ERROR(...)
#    define DBG_LOG_CRITICAL(...)
#    define DBG_LOG_FATAL(...)
#endif
// clang-format on

// Shorthand macro to log and throw a exception which takes a single string
// for construction.
#define LOGGED_THROW(__exception_type, __fmt, ...)                                            \
	do                                                                                        \
	{                                                                                         \
		std::string c_err_ = s_log_sink.build(__fmt, ##__VA_ARGS__);                          \
		s_log_sink.log(Poco::Message::Priority::PRIO_ERROR, __LINE__, "Throwing: " + c_err_); \
		throw __exception_type(c_err_.c_str());                                               \
	} while (false)
