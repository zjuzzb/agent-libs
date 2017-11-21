#pragma once

#include <analyzer.h>
class sinsp_connection_aggregator;
class analyzer_container_state
{
public:
	analyzer_container_state();
	sinsp_host_metrics m_metrics;
	sinsp_counters m_req_metrics;
	sinsp_transaction_counters m_transaction_counters;
	sinsp_delays_info m_transaction_delays;
	vector<vector<sinsp_trlist_entry>> m_server_transactions;
	vector<vector<sinsp_trlist_entry>> m_client_transactions;
	unique_ptr<unordered_map<uint16_t, sinsp_connection_aggregator>> m_connections_by_serverport;

	void set_percentiles(const std::set<double>& percentiles)
	{
		m_metrics.set_percentiles(percentiles);
		m_metrics.m_protostate->set_percentiles(percentiles);
		m_req_metrics.set_percentiles(percentiles);
		m_transaction_counters.set_percentiles(percentiles);
	}

	void set_serialize_pctl_data(bool val)
	{
		m_metrics.set_serialize_pctl_data(val);
		m_metrics.m_protostate->set_serialize_pctl_data(val);
		m_req_metrics.set_serialize_pctl_data(val);
		m_transaction_counters.set_serialize_pctl_data(val);
	}

	// Used to get network stats from /proc/<pid>/net/dev
	uint64_t m_last_bytes_in;
	uint64_t m_last_bytes_out;

	void clear();
};
