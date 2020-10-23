#pragma once

class secure_netsec_internal_metrics
{
public:
	virtual ~secure_netsec_internal_metrics() = default;
	/**
	* Update secure netsec internal metrics.
	*
	* @param[in] n_sent_protobufs the number of sent protobufs.
	* @param[in] flush_time_ms secure netsec flush time in milliseconds.
	*/
	virtual void set_secure_netsec_internal_metrics(int n_sent_protobufs,
						       uint64_t flush_time_ms) = 0;

	/**
	 * Update secure netsec counter for internal metrics.
	 *
	 * @param[in] n_connection_dropped_count The number of dropped connections.
	 * @param[in] n_connection_count The number of TCP connections.
	 * @param[in] n_communication_invalid The number of invalid communications.
	 * @param[in] n_communication_cidr_out The number of communications outside the k8s CIDR.
	 * @param[in] n_communication_cidr_in The number of communications inside the k8s CIDR.
	 * @param[in] n_communication_ingress_count The number of ingress communications.
	 * @param[in] n_communication_egress_count The number of egress communications.
	 * @param[in] n_resolved_client The number of resolved clients.
	 * @param[in] n_resolved_server The number of resolved servers.
	 */
	virtual void set_secure_netsec_sent_counters(int n_connection_dropped_count,
						     int n_connection_count,
						     int n_communication_invalid,
						     int n_communication_cidr_out,
						     int n_communication_cidr_in,
						     int n_communication_ingress_count,
						     int n_communication_egress_count,
						     int n_resolved_owner) = 0;
};
