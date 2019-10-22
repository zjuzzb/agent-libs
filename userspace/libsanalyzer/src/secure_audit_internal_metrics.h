#pragma once

class secure_audit_internal_metrics
{
public:
	virtual ~secure_audit_internal_metrics() = default;
	/**
	* Update secure audit internal metrics.
	*
	* @param[in] n_sent_protobufs the number of sent protobufs.
	* @param[in] flush_time_ms secure audit flush time in milliseconds.
	*/
	virtual void set_secure_audit_internal_metrics(int n_sent_protobufs,
						       uint64_t flush_time_ms) = 0;

	/**
	 * Update secure audit counter for internal metrics.
	 *
	 * @param[in] n_executed_command the number of execute commands.
	 * @param[in] n_connections The number of TCP connections.
	 * @param[in] n_k8s The number of kubernetes events.
	 * @param[in] n_executed_command_dropped the number of execute commands dropped.
	 * @param[in] n_connections_dropped The number of TCP connections dropped.
	 * @param[in] n_k8s_dropped The number of kubernetes events dropped.
	 */
	virtual void set_secure_audit_sent_counters(int n_executed_commands,
						    int n_connections,
						    int n_k8s,
						    int n_executed_commands_dropped,
						    int n_connections_dropped,
						    int n_k8s_dropped,
						    int n_connections_not_interactive_dropped) = 0;
};