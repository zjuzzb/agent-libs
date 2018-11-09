#pragma once

#include "main.h"
#include "internal_metrics.h"
#include <stdarg.h>
#include <token_bucket.h>

class capture_job_handler;
class logger_test;

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
class file_logger
{
public:
	file_logger(const char *file, const char *component);
	void log(uint32_t severity, int line, const char *fmt, ...) const __attribute__ ((format (printf, 4, 5)));
	void log(uint32_t severity, int line, const std::string& str) const;

private:
	std::string build(int line, const char *fmt, va_list& args) const;
	const char *m_component;
	// Filename without extension
	std::string m_file;

	friend class ::logger_test;
};


// Make an instance of a logger in a component that will always print
// the filename and the line number. If prefix is provided then that will
// proceed the filename.
#define DRAGENT_LOGGER(__optional_prefix) \
static const file_logger s_file_logger(__FILE__, "" __optional_prefix)

// Macros to use in the cpp file to interface with the component logger.
#define LOG_TRACE(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_TRACE, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_DEBUG(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_DEBUG, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_INFO(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_INFORMATION, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_NOTICE(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_NOTICE, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_WARNING(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_WARNING, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_ERROR(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_ERROR, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_CRITICAL(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_CRITICAL, __LINE__, __fmt, ##__VA_ARGS__)
#define LOG_FATAL(__fmt, ...) \
s_file_logger.log(Poco::Message::Priority::PRIO_FATAL, __LINE__, __fmt, ##__VA_ARGS__)

extern std::unique_ptr<dragent_logger> g_log;
