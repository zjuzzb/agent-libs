#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <list>
#include "analyzer.h"
#include "common_logger.h"
#include "connectinfo.h"
#include "type_config.h"
#include <secure.pb.h>

#include <nlohmann/json.hpp>

using nlohmann::json;

namespace secure
{
class Audit;
class Connection;
class ExecutedCommand;
class K8sAudit;
} // namespace secure

class sinsp_ipv4_connection_manager;
class sinsp;
class userdb;
class sinsp_executed_command;
class sinsp_connection;

class secure_audit
{
public:
	enum class connection_type
	{
		SRC,
		DST
	};

	secure_audit();
	~secure_audit();

	const secure::Audit* get_events(uint64_t timestamp);
	void clear();
	void flush(uint64_t ts);

	void set_data_handler(secure_audit_data_ready_handler* handler);
	void set_internal_metrics(secure_audit_internal_metrics* internal_metrics);

	void init(sinsp_ipv4_connection_manager* conn);

	void emit_commands_audit(std::unordered_map<std::string, std::vector<sinsp_executed_command>>* executed_commands);
	void emit_connection_async(const _ipv4tuple& tuple, sinsp_connection& conn, sinsp_connection::state_transition transition);
	void emit_k8s_exec_audit();
	void filter_and_append_k8s_audit(const nlohmann::json& j,
					 std::vector<std::string>& k8s_active_filters,
					 std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters);

	static type_config<bool> c_secure_audit_enabled;
	static type_config<bool> c_secure_audit_executed_commands_enabled;
	static type_config<int> c_secure_audit_executed_commands_per_container_limit;
	static type_config<bool> c_secure_audit_k8s_audit_enabled;
	static type_config<bool> c_secure_audit_connections_enabled;
	static type_config<bool> c_secure_audit_connections_local;
	static type_config<bool> c_secure_audit_connections_cmdline;
	static type_config<int> c_secure_audit_connections_cmdline_maxlen;
	static type_config<int> c_secure_audit_executed_commands_limit;
	static type_config<int> c_secure_audit_connections_limit;
	static type_config<int> c_secure_audit_k8s_limit;
	static type_config<int>::mutable_ptr c_secure_audit_frequency;

private:
	void emit_commands_audit_item(std::vector<sinsp_executed_command>* commands, const std::string& container_id);
	void append_connection(connection_type type, const sinsp_connection::state_transition transition, const _ipv4tuple& tuple, sinsp_connection& conn);
	bool filter_k8s_audit(const nlohmann::json& j,
			      std::vector<std::string>& k8s_active_filters,
			      std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters);
	void append_k8s_audit(const std::string& evt);
	void reset_counters();

	secure_audit_data_ready_handler* m_audit_data_handler;
	secure_audit_internal_metrics* m_audit_internal_metrics;
	std::list<std::string> m_k8s_exec_audits;
	secure::Audit* m_secure_audit_batch;
	sinsp_ipv4_connection_manager* m_connection_manager;
	std::unique_ptr<run_on_interval> m_get_events_interval;
	sinsp_analyzer* m_analyzer;
	bool secure_audit_sent;

	int m_executed_commands_count;
	int m_connections_count;
	int m_k8s_audit_count;

	int m_executed_commands_dropped_count;
	int m_connections_dropped_count;
	int m_k8s_audit_dropped_count;
};