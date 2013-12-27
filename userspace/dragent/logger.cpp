#include "logger.h"

dragent_logger* g_log = NULL;

dragent_logger::dragent_logger(Logger* file_log, Logger* console_log)
{
	m_file_log = file_log;
	m_console_log = console_log;
}

void dragent_logger::debug(const string& str)
{
	m_file_log->debug(str);
	if(m_console_log != NULL)
	{
		m_console_log->debug(str);
	}
}

void dragent_logger::information(const string& str)
{
	m_file_log->information(str);
	if(m_console_log != NULL)
	{
		m_console_log->information(str);
	}
}

void dragent_logger::warning(const string& str)
{
	m_file_log->warning(str);
	if(m_console_log != NULL)
	{
		m_console_log->warning(str);
	}
}

void dragent_logger::error(const string& str)
{
	m_file_log->error(str);
	if(m_console_log != NULL)
	{
		m_console_log->error(str);
	}
}

void dragent_logger::critical(const string& str)
{
	m_file_log->critical(str);
	if(m_console_log != NULL)
	{
		m_console_log->critical(str);
	}
}

void dragent_logger::sinsp_logger_callback(char* str, uint32_t sev)
{
	ASSERT(g_log != NULL);

	switch(sev)
	{
	case sinsp_logger::SEV_DEBUG:
		g_log->debug(str);
		break;
	case sinsp_logger::SEV_INFO:
		g_log->information(str);
		break;
	case sinsp_logger::SEV_WARNING:
		g_log->warning(str);
		break;
	case sinsp_logger::SEV_ERROR:
		g_log->error(str);
		break;
	case sinsp_logger::SEV_CRITICAL:
		g_log->critical(str);
		break;
	default:
		ASSERT(false);
	}
}
