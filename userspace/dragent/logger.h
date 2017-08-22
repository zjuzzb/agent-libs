#pragma once

#include "main.h"
#include "internal_metrics.h"
#include <token_bucket.h>

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

private:
	Logger* m_file_log;
	Logger* m_console_log;
	Logger* m_event_log;

	token_bucket m_user_events_tb;
	internal_metrics::sptr_t m_internal_metrics;
};

extern dragent_logger* g_log;
