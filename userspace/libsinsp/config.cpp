#include "sinsp.h"
#include "sinsp_int.h"

sinsp_configuration::sinsp_configuration()
{
	set_connection_timeout_in_sec(DEFAULT_CONNECTION_TIMEOUT_SEC);
	set_thread_timeout_ns(DEFAULT_THREAD_TIMEOUT_SEC * ONE_SECOND_IN_NS);
	set_inactive_thread_scan_time_ns(DEFAULT_INACTIVE_THREAD_SCAN_TIME * ONE_SECOND_IN_NS);
	set_emit_metrics_to_file(false);
	m_machine_id = "<NA>";
	m_customer_id = "<NA>";
	m_analyzer_sample_length_ns = ANALYZER_SAMPLE_LENGTH_NS;
	m_metrics_directory = string(".") + DIR_PATH_SEPARATOR;
}

sinsp_configuration::sinsp_configuration(const sinsp_configuration& configuration)
{
	m_connection_timeout_ns = configuration.m_connection_timeout_ns;
}

uint64_t sinsp_configuration::get_connection_timeout_ns() const
{
	return m_connection_timeout_ns;
}

uint64_t sinsp_configuration::get_connection_timeout_sec() const
{
	return m_connection_timeout_ns / ONE_SECOND_IN_NS;
}

void sinsp_configuration::set_connection_timeout_in_sec(uint64_t timeout_sec)
{
	m_connection_timeout_ns = timeout_sec * ONE_SECOND_IN_NS;
}

bool sinsp_configuration::get_emit_metrics_to_file() const
{
	return m_emit_metrics_to_file;
}

void sinsp_configuration::set_emit_metrics_to_file(bool emit)
{
	m_emit_metrics_to_file = emit;
}

const string& sinsp_configuration::get_metrics_directory() const
{
	return m_metrics_directory;
}

void sinsp_configuration::set_metrics_directory(string metrics_directory)
{
	m_metrics_directory = metrics_directory;
	if(m_metrics_directory[m_metrics_directory.size() - 1] != DIR_PATH_SEPARATOR)
	{
		m_metrics_directory += DIR_PATH_SEPARATOR;
	}
}

uint64_t sinsp_configuration::get_thread_timeout_ns() const
{
	return m_thread_timeout_ns;
}

void sinsp_configuration::set_thread_timeout_ns(uint64_t thread_timeout_ns)
{
	m_thread_timeout_ns = thread_timeout_ns;
}

uint64_t sinsp_configuration::get_inactive_thread_scan_time_ns() const
{
	return m_inactive_thread_scan_time_ns;
}

void sinsp_configuration::set_inactive_thread_scan_time_ns(uint64_t inactive_thread_scan_time_ns)
{
	m_inactive_thread_scan_time_ns = inactive_thread_scan_time_ns;
}

sinsp_logger::output_type sinsp_configuration::get_log_output_type() const
{
	//
	// XXX not implemented yet
	//
	ASSERT(false);
	return sinsp_logger::OT_NONE;
}

void sinsp_configuration::set_log_output_type(sinsp_logger::output_type log_output_type)
{
	if(log_output_type == sinsp_logger::OT_STDOUT)
	{
		g_logger.add_stdout_log();
	}
	else if(log_output_type == sinsp_logger::OT_STDERR)
	{
		g_logger.add_stderr_log();
	}
	else if(log_output_type == sinsp_logger::OT_STDERR)
	{
		g_logger.add_file_log("sisnsp.log");
	}
	else if(log_output_type == sinsp_logger::OT_NONE)
	{
		return;
	}
	else
	{
		ASSERT(false);
		throw sinsp_exception("invalid log output type");
	}
}

const string& sinsp_configuration::get_machine_id() const
{
	return m_machine_id;
}

void sinsp_configuration::set_machine_id(string machine_id)
{
	m_machine_id = machine_id;
}

const string& sinsp_configuration::get_customer_id() const
{
	return m_customer_id;
}

void sinsp_configuration::set_customer_id(string customer_id)
{
	m_customer_id = customer_id;
}

uint64_t sinsp_configuration::get_analyzer_sample_length_ns() const
{
	return m_analyzer_sample_length_ns;
}

void sinsp_configuration::set_analyzer_sample_length_ns(uint64_t analyzer_sample_length_ns)
{
	m_analyzer_sample_length_ns = analyzer_sample_length_ns;
}
