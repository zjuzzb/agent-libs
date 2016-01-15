#ifdef HAS_ANALYZER

#pragma once
#include <bitset>
#include <limits>

using ports_set = bitset<numeric_limits<uint16_t>::max()>;

class SINSP_PUBLIC sinsp_configuration
{
public:
	sinsp_configuration();
	sinsp_configuration(const sinsp_configuration& configuration);
	uint64_t get_connection_timeout_ns() const;
	uint64_t get_connection_timeout_sec() const;
	void set_connection_timeout_in_sec(uint64_t timeout_sec);
	uint64_t get_connection_pruning_interval_ns() const;
	void set_connection_pruning_interval_ns(uint64_t interval_ns);
	bool get_emit_metrics_to_file() const;
	void set_emit_metrics_to_file(bool emit);
	bool get_compress_metrics() const;
	void set_compress_metrics(bool compress);
	const string& get_metrics_directory() const;
	void set_metrics_directory(string metrics_directory);
	sinsp_logger::output_type get_log_output_type() const;
	void set_log_output_type(sinsp_logger::output_type log_output_type);
	const string& get_machine_id() const;
	void set_machine_id(string machine_id);
	const string& get_customer_id() const;
	void set_customer_id(string customer_id);
	uint64_t get_analyzer_sample_len_ns() const;
	uint64_t get_analyzer_original_sample_len_ns() const;
	void set_analyzer_sample_len_ns(uint64_t analyzer_sample_length_ns);
	uint32_t get_max_connection_table_size() const;
	void set_max_connection_table_size(uint32_t max_connection_table_size);
	uint32_t get_max_connections_in_proto() const;
	void set_max_connections_in_proto(uint32_t max_connections_in_proto);
	bool get_aggregate_connections_in_proto() const;
	void set_aggregate_connections_in_proto(bool aggregate);
	bool get_autodrop_enabled() const;
	void set_autodrop_enabled(bool enabled);
	uint32_t get_drop_upper_threshold(uint32_t nprocs) const;
	void set_drop_upper_threshold(uint32_t drop_upper_threshold);
	uint32_t get_drop_lower_threshold(uint32_t nprocs) const;
	void set_drop_lower_threshold(uint32_t drop_lower_threshold);
	uint32_t get_drop_treshold_consecutive_seconds() const;
	void set_drop_treshold_consecutive_seconds(uint32_t drop_treshold_consecutive_seconds);
	const string& get_host_custom_name() const;
	void set_host_custom_name(string host_custom_name);
	const string& get_host_tags() const;
	void set_host_tags(const string& host_tags);
	const bool get_host_hidden() const;
	void set_host_hidden(bool host_hidden);
	const string& get_hidden_processes() const;
	void set_hidden_processes(string hidden_processes);
	const string& get_host_custom_map() const;
	void set_host_custom_map(string host_custom_map);
	const string& get_version() const;
	void set_version(const string& version);
	const string& get_instance_id() const;
	void set_instance_id(const string& instance_id);
	void set_known_ports(const ports_set & v);
	const ports_set & get_known_ports() const;
	void set_blacklisted_ports(const vector<uint16_t> & v);
	void set_blacklisted_ports(const ports_set & v);
	const ports_set & get_blacklisted_ports() const;
	void set_k8s_api_server(const string& k8s_api);
	const string & get_k8s_api_server() const;
	bool get_k8s_autodetect_enabled() const;
	void set_k8s_autodetect_enabled(bool enabled);
	void set_k8s_ssl_ca_certificate(const string& k8s_ssl_ca_cert);
	const string & get_k8s_ssl_ca_certificate() const;
	void set_k8s_ssl_verify_certificate(bool k8s_ssl_ca_cert);
	bool get_k8s_ssl_verify_certificate() const;
	void set_k8s_timeout_ms(int k8s_timeout_ms);
	int get_k8s_timeout_ms() const;
	unsigned get_statsd_limit() const;
	void set_statsd_limit(unsigned value);
	const string & get_mesos_state_uri() const;
	void set_mesos_state_uri(const string & uri);
	const vector<string> & get_marathon_uris() const;
	void set_marathon_uris(const vector<string> & uris);
	bool get_mesos_autodetect_enabled() const;
	void set_mesos_autodetect_enabled(bool enabled);
private:
	uint64_t m_connection_pruning_interval_ns;
	uint64_t m_connection_timeout_ns;
	bool m_emit_metrics_to_file;
	bool m_compress_metrics;
	string m_machine_id;
	string m_customer_id;
	uint64_t m_analyzer_sample_len_ns;
	uint64_t m_analyzer_original_sample_len_ns;
	string m_metrics_directory;
	uint32_t m_max_connection_table_size;
	uint32_t m_max_connections_in_proto;
	bool m_aggregate_connections_in_proto;
	bool m_autodrop_enabled;
	uint32_t m_drop_upper_threshold;
	uint32_t m_drop_lower_threshold;
	uint32_t m_drop_treshold_consecutive_seconds;
	string m_host_custom_name;
	string m_host_tags;
	bool m_host_hidden;
	string m_hidden_processes;
	string m_host_custom_map;
	string m_version;
	string m_instance_id;
	ports_set m_known_ports;
	ports_set m_blacklisted_ports;
	string m_k8s_api;
	bool   m_k8s_autodetect;
	string m_k8s_ssl_ca_certificate;
	bool m_k8s_ssl_verify_certificate;
	int m_k8s_timeout_ms;

	unsigned m_statsd_limit;

	string m_mesos_state_uri;
	vector<string> m_marathon_uris;
	bool   m_mesos_autodetect;
};

#endif // HAS_ANALYZER
