#include <memory>

#include "error_handler.h"

#include "logger.h"
#include "utils.h"

volatile bool dragent_error_handler::m_exception = false;

dragent_error_handler::dragent_error_handler()
{
}

void dragent_error_handler::exception(const Poco::Exception& exc)
{
	g_log->error(exc.displayText());
	m_exception = true;
	dragent_configuration::m_terminate = true;
}
	
void dragent_error_handler::exception(const std::exception& exc)
{
	g_log->error(exc.what());
	m_exception = true;
	dragent_configuration::m_terminate = true;
}

void dragent_error_handler::exception()
{
	g_log->error("Unknown exception");
	m_exception = true;
	dragent_configuration::m_terminate = true;
}

log_reporter::log_reporter(protocol_queue * queue, dragent_configuration * configuration):
		m_queue(queue),
		m_configuration(configuration)
{
}

void log_reporter::send_report(uint64_t ts_ns)
{
	Path p;
	p.parseDirectory(m_configuration->m_log_dir);

	g_log->error("agent didn't terminate cleanly, sending the last "
				 + NumberFormatter::format(m_configuration->m_dirty_shutdown_report_log_size_b)
				 + "B to collector");

	p.setFileName("draios.log");

	FILE* fp = fopen(p.toString().c_str(), "r");
	if(fp == NULL)
	{
		g_log->error(string("fopen: ") + strerror(errno));
		return;
	}

	if(fseek(fp, 0, SEEK_END) == -1)
	{
		g_log->error(string("fseek (1): ") + strerror(errno));
		fclose(fp);
		return;
	}

	long offset = ftell(fp);
	if(offset == -1)
	{
		g_log->error(string("ftell: ") + strerror(errno));
		fclose(fp);
		return;
	}

	if((uint64_t) offset > m_configuration->m_dirty_shutdown_report_log_size_b)
	{
		offset = m_configuration->m_dirty_shutdown_report_log_size_b;
	}

	if(fseek(fp, -offset, SEEK_END) == -1)
	{
		g_log->error(string("fseek (2): ") + strerror(errno));
		fclose(fp);
		return;
	}

	Buffer<char> buf(offset);
	if(fread(buf.begin(), offset, 1, fp) != 1)
	{
		g_log->error("fread error");
		fclose(fp);
		return;
	}

	draiosproto::dirty_shutdown_report report;
	report.set_timestamp_ns(sinsp_utils::get_current_time_ns());
	report.set_customer_id(m_configuration->m_customer_id);
	report.set_machine_id(m_configuration->m_machine_id_prefix + m_configuration->m_machine_id);
	report.set_log(buf.begin(), buf.size());

	std::shared_ptr<protocol_queue_item> report_serialized = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::DIRTY_SHUTDOWN_REPORT,
		report,
		m_configuration->m_compression_enabled);

	if(!report_serialized)
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	if(!m_queue->put(report_serialized, protocol_queue::BQ_PRIORITY_LOW))
	{
		g_log->information("Queue full");
		return;
	}

	fclose(fp);
}