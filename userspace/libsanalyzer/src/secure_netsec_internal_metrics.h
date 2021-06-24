#pragma once

#include <ostream>
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

/*
 * netsec metrics wrapper
 */
class secure_netsec_metric_stats
{
public:
	secure_netsec_metric_stats() = default;
	~secure_netsec_metric_stats() = default;

	bool  add_conn_with_limit(int limit)
	{
		if (limit == 0 || limit > m_connection_count)
		{
			++m_connection_count;
			return true;
		}
		++m_connection_dropped_count;
		return false;
	}

	void comm_invalid() { ++m_communication_invalid; }
	void cidr_out() { ++m_communication_cidr_out; }
	void cidr_in() { ++m_communication_cidr_in; }
	void ingress_added() { ++m_communication_ingress_count; }
	void egress_added() { ++m_communication_egress_count; }
	void owner_resolved() { ++m_resolved_owner; }

	void send_metrics(secure_netsec_internal_metrics& rcv, int nSent, uint64_t flush_time_ms) const
	{
		rcv.set_secure_netsec_internal_metrics(nSent, flush_time_ms);

		rcv.set_secure_netsec_sent_counters(m_connection_dropped_count,
			m_connection_count,
			m_communication_invalid,
			m_communication_cidr_out,
			m_communication_cidr_in,
			m_communication_ingress_count,
			m_communication_egress_count,
			m_resolved_owner
		);
	}

	static void send_empty(secure_netsec_internal_metrics& rcv) {
		(secure_netsec_metric_stats()).send_metrics(rcv, 0, 0);
	}

	friend ostream& operator<<(ostream& os, const secure_netsec_metric_stats& stats)
	{
		os << " secure_netsec_metric_stats ["
		   << " connections=" << stats.m_connection_count
		   <<  "conns_dropped=" << stats.m_connection_dropped_count
		   << " invalid=" << stats.m_communication_invalid
		   << " cidr_out=" << stats.m_communication_cidr_out
		   << " cidr_in=" << stats.m_communication_cidr_in
		   << " ingress_count=" << stats.m_communication_ingress_count
		   << " egress_count=" << stats.m_communication_egress_count
		   << " owners_resolved=" << stats.m_resolved_owner
		   << "]";
		return os;
	}

private:

	// key metrics, and relative pseudo-formulas
	int m_connection_count = 0;
	int m_connection_dropped_count = 0;
	// all connections = invalid + cidr_out + cidr_in
	int m_communication_invalid = 0;
	int m_communication_cidr_out = 0;
	int m_communication_cidr_in = 0;
	// all connections = ingress + egress
	int m_communication_ingress_count = 0;
	int m_communication_egress_count = 0;
	int m_resolved_owner = 0;
};
