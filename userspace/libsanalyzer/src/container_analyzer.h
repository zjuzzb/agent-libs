#pragma once

#include "metrics.h"
#include <delays.h>
#include "protostate.h"
#include "analyzer_file_stat.h"

class infrastructure_state;
class sinsp_connection_aggregator;
class sinsp_configuration;
class analyzer_container_state
{
public:
	analyzer_container_state();
	sinsp_host_metrics m_metrics;
	sinsp_counters m_req_metrics;
	sinsp_transaction_counters m_transaction_counters;
	sinsp_delays_info m_transaction_delays;
	std::vector<std::vector<sinsp_trlist_entry>> m_server_transactions;
	std::vector<std::vector<sinsp_trlist_entry>> m_client_transactions;
	std::unique_ptr<std::unordered_map<uint16_t, sinsp_connection_aggregator>> m_connections_by_serverport;
	analyzer_top_file_stat_map m_files_stat;
	analyzer_top_device_stat_map m_devs_stat;

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
	int64_t m_last_cpu_time;
	std::string m_last_cpuacct_cgroup;

	uint64_t m_reported_count;

	void clear();

	static const uint64_t FILTER_STATE_CACHE_TIME =	10 * ONE_SECOND_IN_NS;
	enum {
		FILT_NONE = 0,
		FILT_EXCL = 1,
		FILT_INCL = 2
	} m_filter_state;
	uint64_t	m_filter_state_ts;

	bool m_matched_generically; // indicates whether a FILT_INCL state was set due to
				    // a match with a specific rule, or a more generic "all"
				    // rule.

	bool should_report_container(const sinsp_configuration *config,
				     const sinsp_container_info *cinfo,
				     const infrastructure_state *infra_state,
				     uint64_t ts,
				     bool& optional);
};
