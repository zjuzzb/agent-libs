#ifdef HAS_ANALYZER

#pragma once

//
// The main analyzer class
//
class sinsp_delays
{
public:
	sinsp_delays(uint32_t ncpus);

	void compute_program_delays(vector<vector<sinsp_trlist_entry>>* host_client_transactions, 
		vector<vector<sinsp_trlist_entry>>* host_server_transactions, sinsp_threadinfo* program_info, OUT sinsp_delays_info* delays);
	void compute_host_container_delays(sinsp_transaction_counters* transaction_counters, 
		vector<vector<sinsp_trlist_entry>>* client_transactions, 
		vector<vector<sinsp_trlist_entry>>* server_transactions, OUT sinsp_delays_info* delays);

VISIBILITY_PRIVATE
	static uint64_t merge_transactions(vector<sinsp_trlist_entry>* intervals, OUT vector<sinsp_trlist_entry>* merge, bool do_sort);
	void compute_program_percpu_delays(vector<vector<sinsp_trlist_entry>>* host_client_transactions, 
		vector<vector<sinsp_trlist_entry>>* host_server_transactions, sinsp_threadinfo* program_info, int32_t cpuid, sinsp_delays_info* delays);
	void compute_host_container_percpu_delays(vector<vector<sinsp_trlist_entry>>* client_transactions, 
		vector<vector<sinsp_trlist_entry>>* server_transactions, int32_t cpuid, sinsp_delays_info* delays);
	static uint64_t prune_client_transactions(vector<vector<sinsp_trlist_entry>>* client_transactions_per_cpu, 
		vector<vector<sinsp_trlist_entry>>* server_transactions_per_cpu);

	int32_t m_num_cpus;
};

#endif // HAS_ANALYZER
