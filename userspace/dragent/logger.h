#pragma once

#include "main.h"

class dragent_logger
{
public:
	dragent_logger(Logger* file_log, Logger* console_log);

	void debug(const string& str);
	void information(const string& str);
	void warning(const string& str);
	void error(const string& str);
	void critical(const string& str);

	static void sinsp_logger_callback(char* str, uint32_t sev);

private:
	Logger* m_file_log;
	Logger* m_console_log;
};

extern dragent_logger* g_log;
