#pragma once

//
// The main analyzer class
//
class sinsp_scores
{
public:
	sinsp_scores(sinsp* inspector);

	//
	// Return the health score for a process
	//
	int32_t get_system_health_score_global(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

	int32_t get_system_health_score_bycpu(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

private:
	sinsp* m_inspector;
};
