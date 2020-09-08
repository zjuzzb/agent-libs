#include "analyzer.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "connectinfo.h"
#include "delays.h"
#include "sched_analyzer.h"
#include "scores.h"
#include "sinsp.h"
#include "sinsp_int.h"

#include <algorithm>

sinsp_scores::sinsp_scores(sinsp_analyzer& analyzer,
                           sinsp* inspector,
                           sinsp_sched_analyzer2* sched_analyzer2)
    : m_analyzer(analyzer),
      m_inspector(inspector),
      m_sched_analyzer2(sched_analyzer2),
      m_sample_length_ns(0)
{
}

//
// Score calculation routine
// See https://drive.google.com/a/draios.com/file/d/0BxPXExNqamb0V3V3MTk3ZlVqQjg/edit?usp=sharing
// and https://drive.google.com/a/draios.com/file/d/0BxPXExNqamb0aUJSTG9qYlFCSVE/edit?usp=sharing
//
float sinsp_scores::calculate_score_5(float ntr,
                                      float ntrcpu,
                                      float nother,
                                      uint32_t n_server_programs)
{
	float score;
	float fnintervals = (float)m_n_intervals_in_sample;

	float maxcpu = MAX(fnintervals / (n_server_programs + 1), fnintervals - nother);

	if (ntrcpu == 0)
	{
		maxcpu = 0;
	}

	score = ntrcpu * 100 / maxcpu;
	ASSERT(score >= 0);

	// Sometimes floating point precision causes the value to go slightly above 100
	if (score > 100)
	{
		ASSERT(score <= 101);
		score = 100;
	}

	return score;
}

sinsp_score_info sinsp_scores::get_system_capacity_score_bycpu_5(sinsp_delays_info* delays,
                                                                 uint32_t n_server_threads,
                                                                 uint64_t sample_end_time,
                                                                 uint64_t sample_duration,
                                                                 thread_analyzer_info* program_info)
{
	sinsp_score_info res(-1, -1);
	int32_t cpuid;

	const scap_machine_info* machine_info = m_inspector->get_machine_info();
	if (machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
	}

	int32_t num_cpus = machine_info->num_cpus;
	ASSERT(num_cpus != 0);

	if (m_sample_length_ns == 0)
	{
		m_sample_length_ns = (size_t)m_analyzer.get_sample_duration();
		m_n_intervals_in_sample =
		    (uint32_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	}

	float max_score = 0;
	float min_score = 200;
	float tot_score = 0;
	uint32_t n_scores = 0;

	float max_score1 = 0;
	float min_score1 = 200;
	float tot_score1 = 0;
	uint32_t n_scores1 = 0;

	std::vector<uint64_t> time_by_concurrency;
	std::vector<int64_t> cpu_counters;

	//
	// Go through the CPUs and calculate the rest time for each of them
	//
	for (cpuid = 0; cpuid < num_cpus; cpuid++)
	{
		cpustate2* cpu_state = &m_sched_analyzer2->m_cpu_states[cpuid];
		float ntr = 0;
		float nother = 0;
		float ntrcpu = 0;
		float idle;

		//
		// Find the union of the time intervals and use it to calculate the time
		// spent serving transactions
		//
		uint64_t tot_time = delays->m_last_percpu_delays[cpuid].m_merged_server_delay;

		if (tot_time > m_sample_length_ns)
		{
			tot_time = m_sample_length_ns;
		}

		ntr = (float)tot_time / CONCURRENCY_OBSERVATION_INTERVAL_NS;

		//
		// Extract the CPU spent while serving transactions
		//
		uint64_t tr_cpu_time;

		if (program_info != NULL)
		{
			ASSERT(program_info->m_procinfo != NULL);

			int32_t nct = (int32_t)program_info->m_procinfo->m_cpu_time_ns.size();

			//
			// This can happen when we drop or filter scheduler events
			//
			if (nct == 0)
			{
				return res;
			}

			ASSERT(nct == num_cpus);

			tr_cpu_time = program_info->m_procinfo->m_cpu_time_ns[cpuid];
		}
		else
		{
			tr_cpu_time = cpu_state->m_lastsample_server_processes_ns;
		}

		ntrcpu = (float)tr_cpu_time * (float)m_n_intervals_in_sample /
		         cpu_state->m_sample_effective_length_ns;

		//
		// Extract the CPU spent not serving transactions
		//
		if (m_analyzer.has_cpu_idle_data())
		{
			idle = (static_cast<float>(m_analyzer.get_cpu_idle_data(cpuid)) *
			        cpu_state->m_sample_effective_length_ns) /
			       100;
		}
		else
		{
			idle = static_cast<float>(cpu_state->m_lastsample_idle_ns);
		}

		float otherns = (float)(cpu_state->m_sample_effective_length_ns - tr_cpu_time - idle);
		if (otherns < 0)
		{
			otherns = 0;
		}

		nother = otherns * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;

		//
		// Score calculation
		//
		if (ntr != 0)
		{
			//
			// Perform score calculation *excluding steal time*.
			// This gives us the *actual* resouce limit.
			//
			const float score =
			    calculate_score_5(ntr,
			                      ntrcpu,
			                      nother,
			                      static_cast<uint32_t>(m_analyzer.num_server_programs()));

			tot_score += score;
			n_scores++;

			if (score > max_score)
			{
				max_score = score;
			}

			if (score < min_score)
			{
				min_score = score;
			}

			//
			// Perform score calculation *including steal time*.
			//
			float score1;

			if (m_analyzer.has_cpu_steal_data())
			{
				const float steal = static_cast<float>(m_analyzer.get_cpu_steal_data(cpuid));

				float ntr1 = ntr * (100 - steal) / 100;
				float nother1 = nother * (100 - steal) / 100;
				float ntrcpu1 = ntrcpu * (100 - steal) / 100;
				float idle1 = m_n_intervals_in_sample - nother1 - ntrcpu1;

				if (idle1 < 0)
				{
					idle1 = 0;
				}

				score1 = calculate_score_5(ntr1,
				                           ntrcpu1,
				                           nother1,
				                           static_cast<uint32_t>(m_analyzer.num_server_programs()));
			}
			else
			{
				score1 = score;
			}

			tot_score1 += score1;
			n_scores1++;

			if (score1 > max_score1)
			{
				max_score1 = score1;
			}

			if (score1 < min_score1)
			{
				min_score1 = score1;
			}
		}
	}

	//
	// Done scanning the transactions, return the average of the CPU rest times.
	// NOTE: if the number of scores (= number of processors that have been
	//       serving transactions) is smaller than the number of *threads* that
	//       have been serving transactions, it means that we have one or servers
	//       that are floating across CPUs. In that case, our number would not have
	//       sense and we return -1, so the global health score will be used.
	//       The exception is when we have only *one* server thread. In that case, we
	//       can safely sum the scores because we know that they are mutually
	//       exclusive.
	//
	if (n_scores != 0 && n_scores <= n_server_threads)
	{
		float nost = tot_score / n_scores;
		float st = tot_score1 / n_scores1;

		res.m_current_capacity = st;
		res.m_stolen_capacity = (nost - st) / nost * 100;
	}
	else if (n_scores != 0 && n_server_threads == 1)
	{
		float nost = MIN(tot_score, 100);
		float st = MIN(tot_score1, 100);
		;

		res.m_current_capacity = st;
		res.m_stolen_capacity = (nost - st) / nost * 100;
	}

	return res;
}

sinsp_score_info sinsp_scores::get_process_capacity_score(thread_analyzer_info* mainthread_info,
                                                          sinsp_delays_info* delays,
                                                          uint32_t n_server_threads,
                                                          uint64_t sample_end_time,
                                                          uint64_t sample_duration)
{
	ASSERT(delays != NULL);

	sinsp_score_info res = get_system_capacity_score_bycpu_5(delays,
	                                                         n_server_threads,
	                                                         sample_end_time,
	                                                         sample_duration,
	                                                         mainthread_info);

	if (mainthread_info->m_procinfo->m_connection_queue_usage_pct > 50)
	{
		res.m_current_capacity =
		    MAX(res.m_current_capacity, mainthread_info->m_procinfo->m_connection_queue_usage_pct);
	}

	return res;
}
