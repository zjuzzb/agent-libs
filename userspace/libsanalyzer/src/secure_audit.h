#pragma once

#include "secure_audit_filter.h"
#include "analyzer.h"
#include "analyzer_fd.h"
#include "analyzer_thread.h"
#include "common_logger.h"
#include "connectinfo.h"
#include "infrastructure_state.h"
#include "type_config.h"

#include <list>
#include <nlohmann/json.hpp>
#include <secure.pb.h>
#include <string>
#include <unordered_map>
#include <vector>

using nlohmann::json;

namespace secure
{
class Audit;
class Connection;
class ExecutedCommand;
class K8sAudit;
}  // namespace secure

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

	void flush(uint64_t ts);

	void set_data_handler(secure_audit_data_ready_handler* handler);
	void set_internal_metrics(secure_audit_internal_metrics* internal_metrics);

	void init(sinsp_ipv4_connection_manager* conn,
	          sinsp_analyzer_fd_listener* analyzer_fd_listener,
	          infrastructure_state* infra_state,
	          sinsp_configuration* configuration);

	void emit_commands_audit(
	    std::unordered_map<std::string, std::vector<sinsp_executed_command>>* executed_commands);
	void emit_connection_async(const _ipv4tuple& tuple,
	                           sinsp_connection& conn,
	                           sinsp_connection::state_transition transition);
	void emit_file_access_async(thread_analyzer_info* tinfo,
	                            uint64_t ts,
	                            const std::string& fullpath,
	                            uint32_t flags);
	void filter_and_append_k8s_audit(
	    const nlohmann::json& j,
	    std::vector<std::string>& k8s_active_filters,
	    std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters,
	    infrastructure_state* infra_state = nullptr);

	static type_config<bool> c_secure_audit_enabled;
	static type_config<bool> c_secure_audit_executed_commands_enabled;
	static type_config<int> c_secure_audit_executed_commands_per_container_limit;
	static type_config<int> c_secure_audit_executed_commands_limit;
	static type_config<bool> c_secure_audit_connections_enabled;
	static type_config<bool> c_secure_audit_file_writes_enabled;
	static type_config<std::vector<std::string>> c_secure_audit_file_writes_exclude;
	static type_config<bool> c_secure_audit_file_writes_cmdline;
	static type_config<bool> c_secure_audit_file_writes_only_interactive;
	static type_config<bool> c_secure_audit_connections_local;
	static type_config<bool> c_secure_audit_connections_cmdline;
	static type_config<int> c_secure_audit_connections_cmdline_maxlen;
	static type_config<bool> c_secure_audit_connections_only_interactive;
	static type_config<int> c_secure_audit_connections_limit;
	static type_config<int> c_secure_audit_file_accesses_limit;
	static type_config<bool> c_secure_audit_k8s_audit_enabled;
	static type_config<int> c_secure_audit_k8s_limit;
	static type_config<int>::mutable_ptr c_secure_audit_frequency;

	// audit labels
	static type_config<bool> c_audit_labels_enabled;
	static type_config<int> c_audit_labels_max_agent_tags;
	static type_config<std::vector<std::string>> c_audit_labels_include;
	static type_config<std::vector<std::string>> c_audit_labels_exclude;

	sinsp_configuration* m_sinsp_configuration;

	std::unordered_set<std::string> m_audit_labels =
	    std::unordered_set<std::string>({"host.hostName",
	                                     "aws.instanceId",
	                                     "aws.accountId",
	                                     "aws.region",
	                                     "agent.tag",
	                                     "container.name",
	                                     "kubernetes.cluster.name",
	                                     "kubernetes.namespace.name",
	                                     "kubernetes.deployment.name",
	                                     "kubernetes.pod.name",
	                                     "kubernetes.node.name"});

	void configure_audit_labels_set();
	void set_audit_labels(const std::string& container_id,
	                      google::protobuf::Map<string, string>* audit_labels);
	void set_audit_label(google::protobuf::Map<std::string, std::string>* audit_labels,
	                     std::string key,
	                     std::string value);

private:
	void emit_commands_audit_item(std::vector<sinsp_executed_command>* commands,
	                              const std::string& container_id);
	void append_connection(connection_type type,
	                       const sinsp_connection::state_transition transition,
	                       const _ipv4tuple& tuple,
	                       sinsp_connection& conn);
	bool filter_k8s_audit(
	    const nlohmann::json& j,
	    std::vector<std::string>& k8s_active_filters,
	    std::unordered_map<std::string, std::unordered_map<std::string, std::string>>& k8s_filters);

	void reset_counters();
	const secure::Audit* get_events(uint64_t timestamp);
	void clear();

	static const std::vector<std::string> BLACKLISTED_FILES;
	std::vector<wildcard_filter<std::string>> m_file_writes_exclude_filters;

	secure_audit_data_ready_handler* m_audit_data_handler;
	infrastructure_state* m_infra_state;
	secure_audit_internal_metrics* m_audit_internal_metrics;
	secure::Audit* m_secure_audit_batch;
	sinsp_ipv4_connection_manager* m_connection_manager;
	sinsp_analyzer_fd_listener* m_analyzer_fd_listener;
	std::unique_ptr<run_on_interval> m_get_events_interval;
	std::shared_ptr<secure_audit_filter> m_secure_audit_filter;
	bool secure_audit_sent;
	bool secure_audit_run;

	int m_executed_commands_count;
	int m_connections_count;
	int m_k8s_audit_count;
	int m_file_accesses_count;

	int m_executed_commands_dropped_count;
	int m_connections_dropped_count;
	int m_k8s_audit_dropped_count;
	int m_file_accesses_dropped_count;

	int m_connections_not_interactive_dropped_count;
	int m_file_accesses_not_interactive_dropped_count;
	int m_k8s_audit_enrich_errors_count;
};
