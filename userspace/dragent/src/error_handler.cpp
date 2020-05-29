#include <memory>
#include <fstream>
#include "error_handler.h"

#include "common_logger.h"
#include "running_state.h"
#include "utils.h"

volatile bool dragent_error_handler::m_exception = false;

#ifndef _WIN32
#ifndef CYGWING_AGENT
#include <execinfo.h>
extern "C" {
	extern thread_local void *exception_backtrace[1024];
	extern thread_local int exception_backtrace_size;
}
#endif
#endif

dragent_error_handler::dragent_error_handler()
{
}

void dragent_error_handler::exception(const Poco::Exception& exc)
{
	g_log->error(exc.displayText());
	dragent::running_state::instance().restart();
}
	
void dragent_error_handler::exception(const std::exception& exc)
{
#ifndef CYGWING_AGENT
#ifndef _WIN32
	glogf(sinsp_logger::SEV_DEBUG, "error_handler: Catching exception %p. Printing backtrace...", &exc);
	static const char s[] = "EXCEPTION BACKTRACE ----------------------";
	static const char e[] = "------------------------------------------";

	char **bt_syms = backtrace_symbols(exception_backtrace, exception_backtrace_size);
	g_log->error(s);
	for (int i = 2; i < exception_backtrace_size; i++)
	{
		g_log->error(bt_syms[i]);
	}
	g_log->error(e);
	free(bt_syms);
#endif
#endif
	g_log->error(exc.what());

	dragent::running_state::instance().restart();
}

void dragent_error_handler::exception()
{
	g_log->error("Unknown exception");
	dragent::running_state::instance().restart();
}

log_reporter::log_reporter(log_report_handler& handler, dragent_configuration * configuration):
		m_report_handler(handler),
		m_configuration(configuration)
{
}

void log_reporter::send_report(protocol_queue& transmit_queue, uint64_t ts_ns)
{
	Path p;
	p.parseDirectory(m_configuration->m_log_dir);

	g_log->error("agent didn't terminate cleanly, sending the last "
				 + NumberFormatter::format(m_configuration->m_dirty_shutdown_report_log_size_b)
				 + "B to collector");

	p.setFileName("draios.log");

	std::ifstream fp(p.toString());
	if (!fp)
	{
		g_log->error(std::string("fopen: ") + strerror(errno));
		return;
	}

	if (!fp.seekg(0, std::ios_base::end))
	{
		g_log->error(std::string("fseek (1): ") + strerror(errno));
		return;
	}

	long offset = fp.tellg();
	if(offset == -1)
	{
		g_log->error(std::string("ftell: ") + strerror(errno));
		return;
	}

	if((uint64_t) offset > m_configuration->m_dirty_shutdown_report_log_size_b)
	{
		offset = m_configuration->m_dirty_shutdown_report_log_size_b;
	}

	if (!fp.seekg(-offset, std::ios_base::end))
	{
		g_log->error(std::string("fseek (2): ") + strerror(errno));
		return;
	}

	Buffer<char> buf(offset);
	if (!fp.read(buf.begin(), offset))
	{
		g_log->error("fread error");
		return;
	}

	draiosproto::dirty_shutdown_report report;
	report.set_timestamp_ns(sinsp_utils::get_current_time_ns());
	report.set_customer_id(m_configuration->m_customer_id);
	report.set_machine_id(m_configuration->machine_id());
	report.set_log(buf.begin(), buf.size());

	std::shared_ptr<serialized_buffer> serialized_report;
	serialized_report = m_report_handler.handle_log_report(ts_ns, report);

	if(!transmit_queue.put(serialized_report, protocol_queue::BQ_PRIORITY_LOW))
	{
		g_log->information("Could not log shutdown report: queue full.");
		return;
	}
}
