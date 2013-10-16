#pragma once

class sinsp_sched_analyzer;

//
// The main analyzer class
//
class sinsp_scores
{
public:
	sinsp_scores(sinsp* inspector, sinsp_sched_analyzer* sched_analyzer);

	//
	// Return the health score for a process
	//
	int32_t get_system_health_score_global(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	int32_t get_system_health_score_bycpu(vector<vector<pair<uint64_t, uint64_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	int32_t get_process_health_score(int32_t system_health_score, 
		sinsp_threadinfo* mainthread_info);
private:
	sinsp* m_inspector;
	sinsp_sched_analyzer* m_sched_analyzer;
//	vector<vector<uint8_t>> m_cpu_transaction_vectors;
	uint64_t m_sample_length_ns;
	uint32_t m_n_intervals_in_sample;
};
