/**
 * @file
 *
 * Interface to common_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "logger.h"
#include <atomic>
#include <exception>
#include <memory>
#include <stdarg.h>
#include <string>
#include <vector>
#include <Poco/Message.h>

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

	common_logger(Poco::Logger* file_log, Poco::Logger* console_log);

	/**
	 * Set the observer that will get notified of logs that get written.
	 */
	void set_observer(log_observer::ptr observer);

	void log(const std::string& str, Poco::Message::Priority sev);
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

private:
	Poco::Logger* const m_file_log;
	Poco::Logger* const m_console_log;
	std::shared_ptr<log_observer> m_observer;
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

	void log(Poco::Message::Priority severity,
	         int line,
	         const char *fmt, ...) const __attribute__ ((format (printf, 4, 5)));
	void log(Poco::Message::Priority severity,
	         int line,
	         const std::string& str) const;
	std::string build(const char *fmt, ...) const;
	const std::string& tag() const { return m_tag; };

private:
	std::string::size_type generate_log(std::vector<char>& log_buffer,
	                                    int line,
	                                    const char* fmt,
	                                    va_list& args) const;
	std::string build(int line, const char *fmt, va_list& args) const;

	// [<optional component>:]<filname without extension>
	const std::string m_tag;
};

extern std::unique_ptr<common_logger> g_log;

// Make an instance of a logger in a component that will always print
// the filename and the line number. If prefix is provided then that will
// proceed the filename.
#define COMMON_LOGGER(__optional_prefix) \
	static const log_sink s_log_sink(__FILE__, "" __optional_prefix)

#define LOG_AT_PRIO_(priority, ...)                                            \
	do                                                                     \
	{                                                                      \
		if(g_log && g_log->is_enabled(priority))                       \
		{                                                              \
			s_log_sink.log((priority), __LINE__, __VA_ARGS__);     \
		}                                                              \
	}                                                                      \
	while(false)

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

// Shorthand macro to log and throw a exception which takes a single string
// for construction.
#define LOGGED_THROW(__exception_type, __fmt, ...)                             \
do {                                                                           \
	std::string c_err_ = s_log_sink.build(__fmt,                           \
					      ##__VA_ARGS__);                  \
	s_log_sink.log(Poco::Message::Priority::PRIO_ERROR,                    \
		       __LINE__,                                               \
		       "Throwing: " + c_err_);                                 \
	throw __exception_type(c_err_.c_str());                                \
} while(false)

