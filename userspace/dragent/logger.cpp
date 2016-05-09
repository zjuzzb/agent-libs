#include "logger.h"

dragent_logger* g_log = NULL;

dragent_logger::dragent_logger(Logger* file_log, Logger* console_log, Logger* event_log):
	m_file_log(file_log),
	m_console_log(console_log),
	m_event_log(event_log)
{
}

//
// regular logging
//

void dragent_logger::trace(const string& str)
{
	m_file_log->trace(str);
	if(m_console_log != NULL)
	{
		m_console_log->trace(str);
	}
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

void dragent_logger::notice(const string& str)
{
	m_file_log->notice(str);
	if(m_console_log != NULL)
	{
		m_console_log->notice(str);
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

void dragent_logger::fatal(const string& str)
{
	m_file_log->fatal(str);
	if(m_console_log != NULL)
	{
		m_console_log->fatal(str);
	}
}

void dragent_logger::trace(string&& str)
{
	m_file_log->trace(str);
	if(m_console_log != NULL)
	{
		m_console_log->trace(str);
	}
}

void dragent_logger::debug(string&& str)
{
	m_file_log->debug(str);
	if(m_console_log != NULL)
	{
		m_console_log->debug(str);
	}
}

void dragent_logger::information(string&& str)
{
	m_file_log->information(str);
	if(m_console_log != NULL)
	{
		m_console_log->information(str);
	}
}

void dragent_logger::notice(string&& str)
{
	m_file_log->notice(str);
	if(m_console_log != NULL)
	{
		m_console_log->notice(str);
	}
}

void dragent_logger::warning(string&& str)
{
	m_file_log->warning(str);
	if(m_console_log != NULL)
	{
		m_console_log->warning(str);
	}
}

void dragent_logger::error(string&& str)
{
	m_file_log->error(str);
	if(m_console_log != NULL)
	{
		m_console_log->error(str);
	}
}

void dragent_logger::critical(string&& str)
{
	m_file_log->critical(str);
	if(m_console_log != NULL)
	{
		m_console_log->critical(str);
	}
}

void dragent_logger::fatal(string&& str)
{
	m_file_log->fatal(str);
	if(m_console_log != NULL)
	{
		m_console_log->fatal(str);
	}
}

//
// user event logging
//

void dragent_logger::fatal_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->fatal(str);
	}
}

void dragent_logger::critical_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->critical(str);
	}
}

void dragent_logger::error_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->error(str);
	}
}

void dragent_logger::warning_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->warning(str);
	}
}

void dragent_logger::notice_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->notice(str);
	}
}

void dragent_logger::information_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->information(str);
	}
}

void dragent_logger::debug_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->debug(str);
	}
}

void dragent_logger::trace_event(const string& str )
{
	if(m_event_log != NULL)
	{
		m_event_log->trace(str);
	}
}

void dragent_logger::fatal_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->fatal(str);
	}
}

void dragent_logger::critical_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->critical(str);
	}
}

void dragent_logger::error_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->error(str);
	}
}

void dragent_logger::warning_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->warning(str);
	}
}

void dragent_logger::notice_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->notice(str);
	}
}

void dragent_logger::information_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->information(str);
	}
}

void dragent_logger::debug_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->debug(str);
	}
}

void dragent_logger::trace_event(string&& str)
{
	if(m_event_log != NULL)
	{
		m_event_log->trace(str);
	}
}

void dragent_logger::sinsp_logger_callback(string&& str, uint32_t sev)
{
	ASSERT(g_log != NULL);

	switch(sev)
	{
	// regular logs
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

	// user-event logs
	case sinsp_logger::SEV_EVT_FATAL:
		g_log->fatal_event(std::move(str));
		break;
	case sinsp_logger::SEV_EVT_CRITICAL:
		g_log->critical_event(std::move(str));
		break;
	case sinsp_logger::SEV_EVT_ERROR:
		g_log->error_event(std::move(str));
		break;
	case sinsp_logger::SEV_EVT_WARNING:
		g_log->warning_event(std::move(str));
		break;
	case sinsp_logger::SEV_EVT_NOTICE:
		g_log->notice_event(std::move(str));
		break;
	case sinsp_logger::SEV_EVT_INFORMATION:
		g_log->information_event(std::move(str));
		break;
	case sinsp_logger::SEV_EVT_DEBUG:
		g_log->debug_event(std::move(str));
		break;
	default:
		ASSERT(false);
	}
}
