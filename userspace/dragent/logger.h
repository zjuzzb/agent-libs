#pragma once

#include "main.h"
#include "internal_metrics.h"
#include <stdarg.h>
#include <token_bucket.h>
#include <vector>

class capture_job_handler;

class avoid_block_channel : public Poco::Channel
{
public:
	avoid_block_channel(const AutoPtr<Poco::FileChannel>& file_channel, const string& machine_id);

	virtual void log(const Poco::Message& message) override;
	virtual void open() override;
	virtual void close() override;

private:
	AutoPtr<Poco::FileChannel> m_file_channel;
	string m_machine_id;
	atomic<bool> m_error_event_sent;
};

class dragent_logger
{
public:
	dragent_logger(Logger* file_log, Logger* console_log, Logger* event_log = NULL);

	void init_user_events_throttling(uint64_t rate, uint64_t max_burst);
	void set_internal_metrics(internal_metrics::sptr_t im)
	{
		m_internal_metrics = im;
	}

	void set_capture_job_handler(capture_job_handler* h)
	{
		m_capture_job_handler = h;
	}

	// regular logging
	void log(const string& str, uint32_t sev);
	void trace(const string& str);
	void debug(const string& str);
	void information(const string& str);
	void notice(const string& str);
	void warning(const string& str);
	void error(const string& str);
	void critical(const string& str);
	void fatal(const string& str);

	void trace(string&& str);
	void debug(string&& str);
	void information(string&& str);
	void notice(string&& str);
	void warning(string&& str);
	void error(string&& str);
	void critical(string&& str);
	void fatal(string&& str);

	// user event logging
	void fatal_event(const string& str );
	void critical_event(const string& str );
	void error_event(const string& str );
	void warning_event(const string& str );
	void notice_event(const string& str );
	void information_event(const string& str );
	void debug_event(const string& str );
	void trace_event(const string& str );

	void fatal_event(string&& str);
	void critical_event(string&& str);
	void error_event(string&& str);
	void warning_event(string&& str);
	void notice_event(string&& str);
	void information_event(string&& str);
	void debug_event(string&& str);
	void trace_event(string&& str);

	static void sinsp_logger_callback(string&& str, uint32_t sev);

	void write_to_memdump(string msg);
private:
	Logger* m_file_log;
	Logger* m_console_log;
	Logger* m_event_log;
	capture_job_handler* m_capture_job_handler;

	token_bucket m_user_events_tb;
	internal_metrics::sptr_t m_internal_metrics;
};

/**
 * Meant to be used inside a cpp file to provide logs targeted
 * to that compilation unit. Do not use this class. Use the
 * DRAGENT_LOGGER and LOG_XYZ macros.
 */
class log_sink
{
public:
	const static size_t DEFAULT_LOG_STR_LENGTH = 256;

	log_sink(const std::string& file, const std::string& component);
	log_sink(std::ostream& out,
	         const std::string& file,
	         const std::string& component);

	void log(uint32_t severity, int line, const char *fmt, ...) const __attribute__ ((format (printf, 4, 5)));
	void log(uint32_t severity, int line, const std::string& str) const;

private:
	/**
	 * Interface to an object that generates log output.
	 */
	class log_output
	{
	public:
		virtual ~log_output() { }
		virtual void log(const std::string& message, int severity) = 0;
	};

	/**
	 * Concrete log_output that writes to the dragent logs.
	 */
	class dragent_log_output : public log_output
	{
	public:
		virtual void log(const std::string& message, int severity) override;
	};

	/**
	 * Concrete log_output that writes to a std::stream.  This is used
	 * only for unit testing.
	 */
	class stream_log_output : public log_output
	{
	public:
		stream_log_output(std::ostream& out);
		virtual void log(const std::string& message, int severity) override;

	private:
		std::ostream& m_out;
	};

	log_sink(log_output* output,
	         const std::string& file,
	         const std::string& component);

	std::string::size_type generate_log(std::vector<char>& log_buffer,
	                                    const int line,
	                                    const char* const fmt,
	                                    va_list& args) const;
	std::string build(int line, const char *fmt, va_list& args) const;

	std::unique_ptr<log_output> m_log_output;

	// [<optional component>:]<filname without extension>
	const std::string m_tag;
};


// Make an instance of a logger in a component that will always print
// the filename and the line number. If prefix is provided then that will
// proceed the filename.
#define DRAGENT_LOGGER(__optional_prefix) \
	static const log_sink s_log_sink(__FILE__, "" __optional_prefix)

#define LOG_AT_PRIO(priority, ...) \
	s_log_sink.log((priority), __LINE__, __VA_ARGS__)

// Macros to use in the cpp file to interface with the component logger.
#define LOG_TRACE(...)     LOG_AT_PRIO(Poco::Message::Priority::PRIO_TRACE,       __VA_ARGS__)
#define LOG_DEBUG(...)     LOG_AT_PRIO(Poco::Message::Priority::PRIO_DEBUG,       __VA_ARGS__)
#define LOG_INFO(...)      LOG_AT_PRIO(Poco::Message::Priority::PRIO_INFORMATION, __VA_ARGS__)
#define LOG_NOTICE(...)    LOG_AT_PRIO(Poco::Message::Priority::PRIO_NOTICE,      __VA_ARGS__)
#define LOG_WARNING(...)   LOG_AT_PRIO(Poco::Message::Priority::PRIO_WARNING,     __VA_ARGS__)
#define LOG_ERROR(...)     LOG_AT_PRIO(Poco::Message::Priority::PRIO_ERROR,       __VA_ARGS__)
#define LOG_CRITICAL(...)  LOG_AT_PRIO(Poco::Message::Priority::PRIO_CRITICAL,    __VA_ARGS__)
#define LOG_FATAL(...)     LOG_AT_PRIO(Poco::Message::Priority::PRIO_FATAL,       __VA_ARGS__)

#if _DEBUG
#    define DBG_LOG_TRACE(...)     LOG_TRACE(__VA_ARGS__)
#    define DBG_LOG_DEBUG(...)     LOG_DEBUG(__VA_ARGS__)
#    define DBG_LOG_INFO(...)      LOG_INFO(__VA_ARGS__)
#    define DBG_LOG_NOTICE(...)    LOG_NOTICE(__VA_ARGS__)
#    define DBG_LOG_WARNING(...)   LOG_WARNING(__VA_ARGS__)
#    define DBG_LOG_ERROR(...)     LOG_ERROR(__VA_ARGS__)
#    define DBG_LOG_CRITICAL(...)  LOG_CRITICAL(__VA_ARGS__)
#    define DBG_LOG_FATAL(...)     LOG_FATAL(__VA_ARGS__)
#else
#    define DBG_LOG_TRACE(...)     do { } while(false)
#    define DBG_LOG_DEBUG(...)     do { } while(false)
#    define DBG_LOG_INFO(...)      do { } while(false)
#    define DBG_LOG_NOTICE(...)    do { } while(false)
#    define DBG_LOG_WARNING(...)   do { } while(false)
#    define DBG_LOG_ERROR(...)     do { } while(false)
#    define DBG_LOG_CRITICAL(...)  do { } while(false)
#    define DBG_LOG_FATAL(...)     do { } while(false)
#endif
extern std::unique_ptr<dragent_logger> g_log;
