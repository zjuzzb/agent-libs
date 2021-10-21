#include <memory>
#include <fstream>
#include "error_handler.h"

#include "common_logger.h"
#include "running_state.h"
#include "utils.h"

#include <Poco/Buffer.h>
#include <Poco/Path.h>
#include <Poco/NumberFormatter.h>

COMMON_LOGGER();

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

void dragent_error_handler::handle_std_exception(const std::exception& exc)
{
    #ifndef CYGWING_AGENT
#ifndef _WIN32
	glogf(sinsp_logger::SEV_DEBUG, "error_handler: Catching exception %p. Printing backtrace...", &exc);
	static const char s[] = "EXCEPTION BACKTRACE ----------------------";
	static const char e[] = "------------------------------------------";

	char **bt_syms = backtrace_symbols(exception_backtrace, exception_backtrace_size);
	LOG_ERROR(s);
	for (int i = 2; i < exception_backtrace_size; i++)
	{
		LOG_ERROR(bt_syms[i]);
	}
	LOG_ERROR(e);
	free(bt_syms);
#endif
#endif
}

void dragent_error_handler::exception(const Poco::Exception& exc)
{
	g_log->error(exc.displayText());
	dragent::running_state::instance().restart();
}
	
void dragent_error_handler::exception(const std::exception& exc)
{
    handle_std_exception(exc);
	LOG_ERROR(exc.what());
	dragent::running_state::instance().restart();
}

void dragent_error_handler::exception()
{
	LOG_ERROR("Unknown exception");
	dragent::running_state::instance().restart();
}

watchdog_error_handler::watchdog_error_handler()
{
}

void watchdog_error_handler::exception(const Poco::Exception& exc)
{
	LOG_ERROR(exc.displayText());
}
	
void watchdog_error_handler::exception(const std::exception& exc)
{
    LOG_ERROR("Hit a std exception %s", exc.what());
    dragent_error_handler::handle_std_exception(exc);
}

void watchdog_error_handler::exception()
{
	LOG_ERROR("Unknown exception");
}

log_reporter::log_reporter(log_report_handler& handler, dragent_configuration * configuration):
		m_report_handler(handler),
		m_configuration(configuration)
{
}

void log_reporter::send_report(protocol_queue& transmit_queue, uint64_t ts_ns)
{
	Poco::Path p;
	p.parseDirectory(m_configuration->m_log_dir);

	LOG_ERROR("agent didn't terminate cleanly, sending the last "
				 + Poco::NumberFormatter::format(m_configuration->m_dirty_shutdown_report_log_size_b)
				 + "B to collector");

	p.setFileName("draios.log");

	std::ifstream fp(p.toString());
	if (!fp)
	{
		LOG_ERROR(std::string("fopen: ") + strerror(errno));
		return;
	}

	if (!fp.seekg(0, std::ios_base::end))
	{
		LOG_ERROR(std::string("fseek (1): ") + strerror(errno));
		return;
	}

	long offset = fp.tellg();
	if(offset == -1)
	{
		LOG_ERROR(std::string("ftell: ") + strerror(errno));
		return;
	}

	if((uint64_t) offset > m_configuration->m_dirty_shutdown_report_log_size_b)
	{
		offset = m_configuration->m_dirty_shutdown_report_log_size_b;
	}

	if (!fp.seekg(-offset, std::ios_base::end))
	{
		LOG_ERROR(std::string("fseek (2): ") + strerror(errno));
		return;
	}

	Poco::Buffer<char> buf(offset);
	if (!fp.read(buf.begin(), offset))
	{
		LOG_ERROR("fread error");
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
		LOG_INFO("Could not log shutdown report: queue full.");
		return;
	}
}
