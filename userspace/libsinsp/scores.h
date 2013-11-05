#pragma once

class sinsp_sched_analyzer;

//
// The main analyzer class
//
class sinsp_scores
{
public:
	sinsp_scores(sinsp* inspector, sinsp_sched_analyzer* sched_analyzer, sinsp_sched_analyzer2* sched_analyzer2);

	//
	// Return the health score for a process
	//
	int32_t get_system_capacity_score_global(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	float get_system_capacity_score_bycpu_3(vector<vector<sinsp_trlist_entry>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration,
		int64_t progid);

	float get_system_capacity_score_bycpu_4(vector<vector<sinsp_trlist_entry>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration, 
		sinsp_threadinfo* program_info,
		float local_remote_ratio);
/*
	int32_t get_system_capacity_score_bycpu(vector<vector<pair<uint64_t, uint64_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	int32_t get_system_capacity_score_bycpu_old(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);
*/
/*
	float get_process_capacity_score(float system_capacity_score, 
		sinsp_threadinfo* mainthread_info);
*/
	float get_process_capacity_score(sinsp_threadinfo* mainthread_info,
		vector<vector<sinsp_trlist_entry>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

private:
	sinsp* m_inspector;
	sinsp_sched_analyzer* m_sched_analyzer;
	sinsp_sched_analyzer2* m_sched_analyzer2;
//	vector<vector<uint8_t>> m_cpu_transaction_vectors;
	uint64_t m_sample_length_ns;
	uint32_t m_n_intervals_in_sample;
};
