#pragma once

class sinsp_sched_analyzer;

class sinsp_score_info
{
public:
	sinsp_score_info(float current_capacity, float stolen_capacity)
	{
		m_current_capacity = current_capacity;
		m_stolen_capacity = stolen_capacity;
	}

	float m_current_capacity;
	float m_stolen_capacity;
};

//
// The main analyzer class
//
class sinsp_scores
{
public:
	sinsp_scores(sinsp_analyzer& analyzer, sinsp* inspector, sinsp_sched_analyzer2* sched_analyzer2);

	sinsp_score_info get_process_capacity_score(sinsp_threadinfo* mainthread_info,
		sinsp_delays_info* delays, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration);

private:
	sinsp_score_info get_system_capacity_score_bycpu_5(sinsp_delays_info* delays, 
		uint32_t n_server_threads,
		uint64_t sample_end_time, uint64_t sample_duration, 
		sinsp_threadinfo* program_info);
	float calculate_score_5(float ntr, float ntrcpu, float nother, uint32_t n_server_programs);

	sinsp_analyzer& m_analyzer;
	sinsp* m_inspector;
	sinsp_sched_analyzer2* m_sched_analyzer2;
	uint64_t m_sample_length_ns;
	uint32_t m_n_intervals_in_sample;
};
