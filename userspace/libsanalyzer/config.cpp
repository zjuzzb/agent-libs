#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"

#ifdef HAS_ANALYZER

sinsp_configuration::sinsp_configuration()
{
	set_connection_timeout_in_sec(DEFAULT_CONNECTION_TIMEOUT_SEC);
	m_connection_pruning_interval_ns = 30 * ONE_SECOND_IN_NS;
	set_emit_metrics_to_file(false);
	set_compress_metrics(false);
	m_machine_id = "<NA>";
	m_customer_id = "<NA>";
	m_analyzer_sample_len_ns = ANALYZER_DEFAULT_SAMPLE_LENGTH_NS;
	m_metrics_directory = string(".") + DIR_PATH_SEPARATOR;
	m_max_connection_table_size = MAX_CONNECTION_TABLE_SIZE;
	m_max_connections_in_proto = DEFAULT_MAX_CONNECTIONS_IN_PROTO;
	m_aggregate_connections_in_proto = AGGREGATE_CONNECTIONS_IN_PROTO;
	m_autodrop_enabled = AUTODROP_ENABLED;
	m_drop_upper_threshold = DROP_UPPER_THRESHOLD;
	m_drop_lower_threshold = DROP_LOWER_THRESHOLD;
	m_drop_treshold_consecutive_seconds = DROP_THRESHOLD_CONSECUTIVE_SECONDS;
	m_host_hidden = false;

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

uint64_t sinsp_configuration::get_connection_pruning_interval_ns() const
{
	return m_connection_pruning_interval_ns;
}

void sinsp_configuration::set_connection_pruning_interval_ns(uint64_t interval_ns)
{
	m_connection_pruning_interval_ns = interval_ns;
}

bool sinsp_configuration::get_emit_metrics_to_file() const
{
	return m_emit_metrics_to_file;
}

void sinsp_configuration::set_emit_metrics_to_file(bool emit)
{
	m_emit_metrics_to_file = emit;
}

bool sinsp_configuration::get_compress_metrics() const
{
	return m_compress_metrics;
}

void sinsp_configuration::set_compress_metrics(bool emit)
{
	m_compress_metrics = emit;
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
	g_logger.set_log_output_type(log_output_type);
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

uint64_t sinsp_configuration::get_analyzer_sample_len_ns() const
{
	return m_analyzer_sample_len_ns;
}

void sinsp_configuration::set_analyzer_sample_len_ns(uint64_t analyzer_sample_length_ns)
{
	m_analyzer_sample_len_ns = analyzer_sample_length_ns;
}

uint32_t sinsp_configuration::get_max_connection_table_size() const
{
	return m_max_connection_table_size;
}

void sinsp_configuration::set_max_connection_table_size(uint32_t max_connection_table_size)
{
	m_max_connection_table_size = max_connection_table_size;
}

uint32_t sinsp_configuration::get_max_connections_in_proto() const
{
	return m_max_connections_in_proto;
}

void sinsp_configuration::set_max_connections_in_proto(uint32_t max_connections_in_proto)
{
	m_max_connections_in_proto = max_connections_in_proto;
}

bool sinsp_configuration::get_aggregate_connections_in_proto() const
{
	return m_aggregate_connections_in_proto;
}

void sinsp_configuration::set_aggregate_connections_in_proto(bool aggregate)
{
	m_aggregate_connections_in_proto = aggregate;
}

bool sinsp_configuration::get_autodrop_enabled() const
{
	return m_autodrop_enabled;
}

void sinsp_configuration::set_autodrop_enabled(bool enabled)
{
	if(enabled)
	{
		m_autodrop_enabled = true;
	}
	else
	{
		//m_inspector->stop_dropping_mode();
		m_autodrop_enabled = false;	
	}
}

uint32_t sinsp_configuration::get_drop_upper_threshold(uint32_t nprocs) const
{
	//return 5;
	if(nprocs > 0)
	{
		return MIN((m_drop_upper_threshold + (m_drop_upper_threshold * (nprocs - 1) * 6 / 10)), 100);
	}
	else
	{
		return m_drop_upper_threshold;
		ASSERT(false);
	}
}

void sinsp_configuration::set_drop_upper_threshold(uint32_t drop_upper_threshold)
{
	m_drop_upper_threshold = drop_upper_threshold;
}

uint32_t sinsp_configuration::get_drop_lower_threshold(uint32_t nprocs) const
{
	//return 3;
	if(nprocs > 0)
	{
		return MIN(m_drop_lower_threshold + (m_drop_lower_threshold * (nprocs - 1) * 7 / 10), 90);
	}
	else
	{
		return m_drop_lower_threshold;
		ASSERT(false);
	}
}

void sinsp_configuration::set_drop_lower_threshold(uint32_t drop_lower_threshold)
{
	m_drop_lower_threshold = drop_lower_threshold;
}

uint32_t sinsp_configuration::get_drop_treshold_consecutive_seconds() const
{
	return m_drop_treshold_consecutive_seconds;
}

void sinsp_configuration::set_drop_treshold_consecutive_seconds(uint32_t drop_treshold_consecutive_seconds)
{
	m_drop_treshold_consecutive_seconds = drop_treshold_consecutive_seconds;
}

const string& sinsp_configuration::get_host_custom_name() const
{
	return m_host_custom_name;
}

void sinsp_configuration::set_host_custom_name(string host_custom_name)
{
	m_host_custom_name = host_custom_name;
}

const string& sinsp_configuration::get_host_tags() const
{
	return m_host_tags;
}

void sinsp_configuration::set_host_tags(const string& host_tags)
{
	m_host_tags = host_tags;
}

const bool sinsp_configuration::get_host_hidden() const
{
	return m_host_hidden;
}

void sinsp_configuration::set_host_hidden(bool host_hidden)
{
	m_host_hidden = host_hidden;
}

const string& sinsp_configuration::get_hidden_processes() const
{
	return m_hidden_processes;
}

void sinsp_configuration::set_hidden_processes(string hidden_processes)
{
	m_hidden_processes = hidden_processes;
}

const string& sinsp_configuration::get_host_custom_map() const
{
	return m_host_custom_map;
}

void sinsp_configuration::set_host_custom_map(string host_custom_map)
{
	m_host_custom_map = host_custom_map;
}

const string& sinsp_configuration::get_version() const
{
	return m_version;
}

void sinsp_configuration::set_version(const string& version)
{
	m_version = version;
}

const string& sinsp_configuration::get_instance_id() const
{
	return m_instance_id;
}

void sinsp_configuration::set_instance_id(const string& instance_id)
{
	m_instance_id = instance_id;
}

#endif // HAS_ANALYZER
