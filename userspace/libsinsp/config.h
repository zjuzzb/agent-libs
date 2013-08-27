#pragma once

class SINSP_PUBLIC sinsp_configuration
{
public:
	sinsp_configuration();
	sinsp_configuration(const sinsp_configuration& configuration);
	uint64_t get_connection_timeout_ns() const;
	uint64_t get_connection_timeout_sec() const;
	void set_connection_timeout_in_sec(uint64_t timeout_sec);
	bool get_emit_metrics_to_file() const;
	void set_emit_metrics_to_file(bool emit);
	const string& get_metrics_directory() const;
	void set_metrics_directory(string metrics_directory);
	uint64_t get_thread_timeout_ns() const;
	void set_thread_timeout_ns(uint64_t thread_timeout_ns);
	uint64_t get_inactive_thread_scan_time_ns() const;
	void set_inactive_thread_scan_time_ns(uint64_t inactive_thread_scan_time_ns);
	sinsp_logger::output_type get_log_output_type() const;
	void set_log_output_type(sinsp_logger::output_type log_output_type);
	const string& get_machine_id() const;
	void set_machine_id(string machine_id);
	const string& get_customer_id() const;
	void set_customer_id(string customer_id);
	uint64_t get_analyzer_sample_length_ns() const;
	void set_analyzer_sample_length_ns(uint64_t analyzer_sample_length_ns);
	uint32_t get_max_connection_table_size() const;
	void set_max_connection_table_size(uint32_t max_connection_table_size);
	uint32_t get_max_thread_table_size() const;
	void set_max_thread_table_size(uint32_t max_thread_table_size);

private:
	uint64_t m_connection_timeout_ns;
	bool m_emit_metrics_to_file;
	uint64_t m_thread_timeout_ns;
	uint64_t m_inactive_thread_scan_time_ns;
	string m_machine_id;
	string m_customer_id;
	uint64_t m_analyzer_sample_length_ns;
	string m_metrics_directory;
	uint32_t m_max_connection_table_size;
	uint32_t m_max_thread_table_size;
};
