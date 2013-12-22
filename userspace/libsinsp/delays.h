#pragma once

class sinsp_percpu_delays
{
public:
	void clear()
	{
		m_last_server_transaction_union.clear();
		m_last_client_transaction_union.clear();
	}

	vector<sinsp_trlist_entry> m_last_server_transaction_union;
	vector<sinsp_trlist_entry> m_last_client_transaction_union;
	uint64_t m_merged_server_delay;
	uint64_t m_merged_client_delay;
};

class sinsp_delays_info
{
public:
	void clear()
	{
		m_merged_server_delay = 0;
		m_merged_client_delay = 0;
	}

	vector<sinsp_percpu_delays> m_last_percpu_delays;
	double m_local_remote_ratio;
	uint64_t m_merged_server_delay;
	uint64_t m_merged_client_delay;
	int64_t m_local_processing_delay_ns;
};

//
// The main analyzer class
//
class sinsp_delays
{
public:
	sinsp_delays(sinsp_analyzer* analyzer, uint32_t ncpus);

	void compute_program_delays(sinsp_threadinfo* program_info, OUT sinsp_delays_info* delays);
	void compute_host_delays(OUT sinsp_delays_info* delays);

VISIBILITY_PRIVATE
	static uint64_t merge_transactions(vector<sinsp_trlist_entry>* intervals, OUT vector<sinsp_trlist_entry>* merge);
	void compute_program_percpu_delays(sinsp_threadinfo* program_info, int32_t cpuid, sinsp_delays_info* delays);
	void compute_host_percpu_delays(int32_t cpuid, sinsp_delays_info* delays);
	static uint64_t prune_client_transactions(vector<vector<sinsp_trlist_entry>>* client_transactions_per_cpu, 
		vector<vector<sinsp_trlist_entry>>* server_transactions_per_cpu);

	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	int32_t m_num_cpus;
};
