#include "logger.h"
#include <sys/statvfs.h>
#include "configuration.h"
#include "capture_job_handler.h"

using namespace Poco;
using Poco::Message;

unique_ptr<dragent_logger> g_log;

dragent_logger::dragent_logger(Logger* file_log, Logger* console_log, Logger* event_log):
	m_file_log(file_log),
	m_console_log(console_log),
	m_event_log(event_log)
{
	m_capture_job_handler = NULL;
}

void dragent_logger::init_user_events_throttling(uint64_t rate, uint64_t max_burst)
{
	m_user_events_tb.init(rate, max_burst);
}

//
// regular logging
//

void dragent_logger::log(const string& str, uint32_t sev)
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
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_DEBUG);
	}
}

void dragent_logger::information(const string& str)
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
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_WARNING);
	}
}

void dragent_logger::error(const string& str)
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
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_DEBUG);
	}
}

void dragent_logger::information(string&& str)
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
	if(m_internal_metrics)
	{
		m_internal_metrics->notify(Message::Priority::PRIO_WARNING);
	}
}

void dragent_logger::error(string&& str)
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

	// For user event severities, only log the event if allowed by
	// the token bucket.

	if (sev >= sinsp_logger::SEV_EVT_MIN &&
	    sev <= sinsp_logger::SEV_EVT_MAX)
	{
		if (! g_log->m_user_events_tb.claim())
		{
			g_log->warning("User event throttled: msg=" + str);
			return;
		}
	}

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

	// Memdumper logs
	case sinsp_logger::SEV_EVT_MDUMP:
		g_log->write_to_memdump(str);
		break;
	default:
		ASSERT(false);
	}
}

void dragent_logger::write_to_memdump(string msg)
{
	try
	{
		yaml_configuration yaml(msg);
		string name = yaml.get_scalar<string>("name");
		string desc = yaml.get_scalar<string>("description", "");
		string scope = yaml.get_scalar<string>("scope", "");
		std::unordered_map<std::string, std::string> tags = yaml.get_merged_map<string>("tags");

		m_capture_job_handler->push_infra_event(sinsp_utils::get_current_time_ns(), 0, "docker", name, desc, scope);
	}
	catch(YAML::ParserException& ex)
	{
		return;
	}
}

avoid_block_channel::avoid_block_channel(const AutoPtr<Poco::FileChannel>& file_channel, const string& machine_id):
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
			string fname = m_file_channel->getProperty("path");
			struct statvfs buf;
			if(0 == statvfs(fname.c_str(), &buf))
			{
				ostringstream os;
				os << "Logger (" << fname << "): [" << ex.displayText() << ']' << std::endl <<
					"disk free=" << buf.f_bsize * buf.f_bfree / 1024 << " kb";
				unordered_map<string, string> tags{{"source", "dragent"}};
				g_log->error_event(sinsp_user_event::to_string(get_epoch_utc_seconds_now(),
					"DragentLoggerError", os.str(), event_scope("host.mac", m_machine_id), move(tags)));
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
