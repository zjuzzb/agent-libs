#pragma once

#include <analyzer.h>
class sinsp_connection_aggregator;
class analyzer_container_state
{
public:
	typedef std::unordered_map<std::string, int> proc_count_map_t;
	analyzer_container_state();
	sinsp_host_metrics m_metrics;
	sinsp_counters m_req_metrics;
	sinsp_transaction_counters m_transaction_counters;
	sinsp_delays_info m_transaction_delays;
	vector<vector<sinsp_trlist_entry>> m_server_transactions;
	vector<vector<sinsp_trlist_entry>> m_client_transactions;
	string m_memory_cgroup;
	unique_ptr<unordered_map<uint16_t, sinsp_connection_aggregator>> m_connections_by_serverport;
	proc_count_map_t m_proc_container_count;
	proc_count_map_t m_proc_start_container_count;
};
