#include <algorithm>

#include "sinsp.h"
#include "sinsp_int.h"
#include "../../driver/ppm_ringbuffer.h"

#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"
#include "delays.h"
#include "scores.h"
#include "sched_analyzer.h"
#include "analyzer_thread.h"

sinsp_scores::sinsp_scores(sinsp* inspector, sinsp_sched_analyzer2* sched_analyzer2)
{
	m_inspector = inspector;
	m_sched_analyzer2 = sched_analyzer2;
	m_sample_length_ns = 0;
}

// int32_t sinsp_scores::get_system_capacity_score_global(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
// 	uint32_t n_server_threads,
// 	uint64_t sample_end_time, uint64_t sample_duration)
// {
// 	uint32_t trsize = (uint32_t)transactions->size();
// 	const scap_machine_info* machine_info = m_inspector->get_machine_info();
// 	if(machine_info == NULL)
// 	{
// 		ASSERT(false);
// 		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
// 	}

// 	//
// 	// How the algorithm works at high level: 
// 	//   measure for transaction "gaps", i.e. time intervals in which no transaction
// 	//   is served. Sum the gaps and divide the sum by the sample time. The number
// 	//   is our health score, and measures the capacity that this process still has
// 	//   to serve transactions.
// 	// In practice, we use a couple of tricks:
// 	//   - we don't apply the algorithm to the full sample, but to the interval between the 
// 	//     sample start time and the end of the last transaction. After that we normalize the
// 	//     result as if it were a full sample. The reason is: we catch the transactions only
// 	//     after the next direction switch so, especially when the number of requests is very low,
// 	//     the last part of the sample might not contain transactions just because they are
// 	//     still in progress. We don't want that to skew the results.
// 	//   - we subdivide the sample time into intervals of CONCURRENCY_OBSERVATION_INTERVAL_NS nanoseconds,
// 	//     and we count the number of concurrent transactions for each interval. In other
// 	//     words, we "digitalize" the interval intersections, so that we never have more than
// 	//     (sample time / CONCURRENCY_OBSERVATION_INTERVAL_NS) of them.
// 	//
// 	if(trsize != 0)
// 	{
// 		uint64_t j;
// 		uint32_t k;
// 		uint64_t starttime = sample_end_time - sample_duration;
// 		uint64_t endtime = sample_end_time;
// //		uint64_t endtime = m_transactions[trsize - 1].second / CONCURRENCY_OBSERVATION_INTERVAL_NS * CONCURRENCY_OBSERVATION_INTERVAL_NS; // starttime + sample_duration; 
// 		int64_t actual_sample_duration = (endtime > starttime)? endtime - starttime : 0;
// 		uint32_t concurrency;
// 		vector<uint64_t> time_by_concurrency;
// 		int64_t rest_time;

// 		//
// 		// Create the concurrency intervals vector
// 		//
// 		for(k = 0; k < MAX_HEALTH_CONCURRENCY; k++)
// 		{
// 			time_by_concurrency.push_back(0);
// 		}
// /*
// vector<uint64_t>v;
// uint64_t tot = 0;
// for(k = 0; k < trsize; k++)
// {
// 	uint64_t delta = (*transactions)[k].second.first - (*transactions)[k].first;
// 	v.push_back(delta);
// 	tot += delta;
// }
// */
// 		//
// 		// Make sure the transactions are ordered by start time
// 		//
// 		std::sort(transactions->begin(), transactions->end());

// 		//
// 		// Count the number of concurrent transactions for each inerval of size
// 		// CONCURRENCY_OBSERVATION_INTERVAL_NS.
// 		//
// 		for(j = starttime; j < endtime; j+= CONCURRENCY_OBSERVATION_INTERVAL_NS)
// 		{
// 			concurrency = 0;

// 			for(k = 0; k < trsize; k++)
// 			{
// 				if((*transactions)[k].first <= j)
// 				{
// 					if((*transactions)[k].second.first >= j)
// 					{
// 						concurrency++;
// 					}
// 				}
// 				else
// 				{
// 					break;
// 				}
// 			}

// 			if(concurrency < MAX_HEALTH_CONCURRENCY)
// 			{
// 				time_by_concurrency[concurrency] += CONCURRENCY_OBSERVATION_INTERVAL_NS;
// 			}
// 			else
// 			{
// 				break;
// 			}
// 		}

// 		//
// 		// Infer the rest time by subtracting the amouny of time spent at each concurrency
// 		// level from the sample time.
// 		//
// 		rest_time = 0;
		
// 		if(machine_info)
// 		{
// 			if(n_server_threads > machine_info->num_cpus)
// 			{
// 				n_server_threads = machine_info->num_cpus;
// 			}
// 		}
// 		else
// 		{
// 			ASSERT(false);
// 			return -1;
// 		}

// 		for(k = 0; k < n_server_threads; k++)
// 		{
// 			rest_time += time_by_concurrency[k];
// 		}

// 		if(actual_sample_duration != 0)
// 		{
// 			return (int32_t)(100LL - rest_time * 100 / actual_sample_duration);
// 		}
// 		else
// 		{
// 			return 100;
// 		}
// 	}

// 	return -1;
// }

//
// Score calculation routine
// See https://drive.google.com/a/draios.com/file/d/0BxPXExNqamb0V3V3MTk3ZlVqQjg/edit?usp=sharing and 
// https://drive.google.com/a/draios.com/file/d/0BxPXExNqamb0aUJSTG9qYlFCSVE/edit?usp=sharing
//
// float sinsp_scores::calculate_score_4(float ntr, float ntrcpu, float nother, uint32_t n_server_programs)
// {
// 	float score;
// 	float avail;
// 	float fnintervals = (float)m_n_intervals_in_sample;

// 	float maxcpu = MAX(fnintervals / (n_server_programs + 1), 
// 	//float maxcpu = MAX(fnintervals / 2,
// 		fnintervals - nother);

// 	if(ntrcpu != 0)
// 	{
// 		avail = MIN(fnintervals, ntr * maxcpu / ntrcpu);
// 	}
// 	else
// 	{
// 		avail = fnintervals;
// 	}

// 	float maxavail = MAX(avail, ntr);
// 	score = ntr * 100 / maxavail;
// 	ASSERT(score >= 0);

// 	// Sometimes floating point precision causes the value to go slightly above 100
// 	if(score > 100)
// 	{
// 		ASSERT(score <= 101);
// 		score = 100;
// 	}

// 	return score;
// }

// sinsp_score_info sinsp_scores::get_system_capacity_score_bycpu_4(sinsp_delays_info* delays,
// 	uint32_t n_server_threads, 	uint64_t sample_end_time, uint64_t sample_duration, sinsp_threadinfo* program_info)
// {
// 	sinsp_score_info res(-1,  -1);
// 	int32_t cpuid;

// 	const scap_machine_info* machine_info = m_inspector->get_machine_info();
// 	if(machine_info == NULL)
// 	{
// 		ASSERT(false);
// 		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
// 	}

// 	int32_t num_cpus = machine_info->num_cpus;
// 	ASSERT(num_cpus != 0);

// 	if(m_sample_length_ns == 0)
// 	{
// 		m_sample_length_ns = (size_t)m_inspector->m_analyzer->m_configuration->get_analyzer_sample_len_ns();
// 		m_n_intervals_in_sample = (uint32_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS;
// 	}

// 	float max_score = 0;
// 	float min_score = 200;
// 	float tot_score = 0;
// 	uint32_t n_scores = 0;

// 	float max_score1 = 0;
// 	float min_score1 = 200;
// 	float tot_score1 = 0;
// 	uint32_t n_scores1 = 0;

// 	vector<uint64_t> time_by_concurrency;
// 	vector<int64_t> cpu_counters;

// 	//
// 	// Go through the CPUs and calculate the rest time for each of them
// 	//
// 	for(cpuid = 0; cpuid < num_cpus; cpuid++)
// 	{
// 		cpustate2* cpu_state = &m_sched_analyzer2->m_cpu_states[cpuid];
// 		float ntr = 0;
// 		float nother = 0;
// 		float ntrcpu = 0;
// 		float idle;

// 		//
// 		// Find the union of the time intervals and use it to calculate the time 
// 		// spent serving transactions
// 		//
// 		uint64_t tot_time = delays->m_last_percpu_delays[cpuid].m_merged_server_delay;

// 		if(tot_time > m_sample_length_ns)
// 		{
// 			tot_time = m_sample_length_ns;
// 		}

// 		ntr = (float)tot_time / CONCURRENCY_OBSERVATION_INTERVAL_NS;

// 		//
// 		// Extract the CPU spent while serving transactions
// 		//
// 		uint64_t tr_cpu_time;

// 		if(program_info != NULL)
// 		{
// 			ASSERT(program_info->m_ainfo->m_procinfo != NULL);

// 			int32_t nct = (int32_t)program_info->m_ainfo->m_procinfo->m_cpu_time_ns.size();

// 			//
// 			// This can happen when we drop or filter scheduler events
// 			//
// 			if(nct == 0)
// 			{
// 				return res;
// 			}

// 			ASSERT(nct == num_cpus);

// 			tr_cpu_time = program_info->m_ainfo->m_procinfo->m_cpu_time_ns[cpuid];
// 		}
// 		else
// 		{
// 			tr_cpu_time = cpu_state->m_lastsample_server_processes_ns;
// 		}

// 		ntrcpu = (float)tr_cpu_time * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;

// 		//
// 		// Extract the CPU spent not serving transactions
// 		//
// 		if(m_inspector->m_analyzer->m_cpu_idles.size() != 0)
// 		{
// 			idle = (((float)m_inspector->m_analyzer->m_cpu_idles[cpuid]) * cpu_state->m_sample_effective_length_ns) / 100;
// 		}
// 		else
// 		{
// 			idle = (float)cpu_state->m_lastsample_idle_ns;
// 		}

// 		float otherns = (float)(cpu_state->m_sample_effective_length_ns - tr_cpu_time - idle);
// 		if(otherns < 0)
// 		{
// 			otherns = 0;
// 		}

// 		nother = otherns * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;

// 		//
// 		// Score calculation
// 		//
// 		ntr *= (float)delays->m_local_remote_ratio;

// 		if(ntr != 0)
// 		{
// 			//
// 			// Perform score calculation *excluding steal time*.
// 			// This gives us the *actual* resouce limit.
// 			//
// 			float score = calculate_score_4(ntr, ntrcpu, nother, 
// 				(uint32_t)m_inspector->m_analyzer->num_server_programs());

// 			tot_score += score;
// 			n_scores++;

// 			if(score > max_score)
// 			{
// 				max_score = score;
// 			}

// 			if(score < min_score)
// 			{
// 				min_score = score;
// 			}

// 			//
// 			// Perform score calculation *including steal time*.
// 			//
// 			float score1;

// 			if(m_inspector->m_analyzer->m_cpu_steals.size() != 0)
// 			{
// 				float steal = (float)(m_inspector->m_analyzer->m_cpu_steals[cpuid]);

// 				float ntr1 = ntr * (100 - steal) / 100;
// 				float nother1 = nother * (100 - steal) / 100;
// 				float ntrcpu1 = ntrcpu * (100 - steal) / 100;
// 				float idle1 = m_n_intervals_in_sample - nother1 - ntrcpu1;

// 				if(idle1 < 0)
// 				{
// 					ASSERT(false);
// 					idle1 = 0;
// 				}

// 				score1 = calculate_score_4(ntr1, ntrcpu1, nother1,
// 					(uint32_t)m_inspector->m_analyzer->num_server_programs());
// 			}
// 			else
// 			{
// 				score1 = score;
// 			}

// 			tot_score1 += score1;
// 			n_scores1++;

// 			if(score1 > max_score1)
// 			{
// 				max_score1 = score1;
// 			}

// 			if(score1 < min_score1)
// 			{
// 				min_score1 = score1;
// 			}
// 		}
// 	}

// 	//
// 	// Done scanning the transactions, return the average of the CPU rest times.
// 	// NOTE: if the number of scores (= number of processors that have been 
// 	//       serving transactions) is smaller than the number of *threads* that 
// 	//       have been serving transactions, it means that we have one or servers 
// 	//       that are floating across CPUs. In that case, our number would not have 
// 	//       sense and we return -1, so the global health score will be used.
// 	//       The exception is when we have only *one* server thread. In that case, we 
// 	//       can safely sum the scores because we know that they are mutually 
// 	//       exclusive.
// 	//
// 	if(n_scores != 0 && n_scores <= n_server_threads)
// 	{
// 		//g_logger.format(sinsp_logger::SEV_DEBUG,
// 		//	">>%.2f-%.2f-%.2f (%" PRId32 ")",
// 		//	min_score,
// 		//	max_score,
// 		//	tot_score / n_scores,
// 		//	n_scores);
// 		float nost = tot_score / n_scores;
// 		float st = tot_score1 / n_scores1;

// 		res.m_current_capacity = st;
// 		res.m_stolen_capacity = (nost - st) / nost * 100;
// 	}
// 	else if(n_scores != 0 && n_server_threads == 1)
// 	{
// 		float nost = MIN(tot_score, 100);
// 		float st = MIN(tot_score1, 100);;

// 		res.m_current_capacity = st;
// 		res.m_stolen_capacity = (nost - st) / nost * 100;
// 	}

// 	return res;
// }

//
// Score calculation routine
// See https://drive.google.com/a/draios.com/file/d/0BxPXExNqamb0V3V3MTk3ZlVqQjg/edit?usp=sharing and 
// https://drive.google.com/a/draios.com/file/d/0BxPXExNqamb0aUJSTG9qYlFCSVE/edit?usp=sharing
//
float sinsp_scores::calculate_score_5(float ntr, float ntrcpu, float nother, uint32_t n_server_programs)
{
	float score;
	float fnintervals = (float)m_n_intervals_in_sample;

	float maxcpu = MAX(fnintervals / (n_server_programs + 1), fnintervals - nother);

	if(ntrcpu == 0)
	{
		maxcpu = 0;
	}

	score = ntrcpu * 100 / maxcpu;
	ASSERT(score >= 0);

	// Sometimes floating point precision causes the value to go slightly above 100
	if(score > 100)
	{
		ASSERT(score <= 101);
		score = 100;
	}

	return score;
}

sinsp_score_info sinsp_scores::get_system_capacity_score_bycpu_5(sinsp_delays_info* delays,
	uint32_t n_server_threads, 	uint64_t sample_end_time, uint64_t sample_duration, sinsp_threadinfo* program_info)
{
	sinsp_score_info res(-1,  -1);
	int32_t cpuid;

	const scap_machine_info* machine_info = m_inspector->get_machine_info();
	if(machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
	}

	int32_t num_cpus = machine_info->num_cpus;
	ASSERT(num_cpus != 0);

	if(m_sample_length_ns == 0)
	{
		m_sample_length_ns = (size_t)m_inspector->m_analyzer->m_configuration->get_analyzer_sample_len_ns();
		m_n_intervals_in_sample = (uint32_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	}

	float max_score = 0;
	float min_score = 200;
	float tot_score = 0;
	uint32_t n_scores = 0;

	float max_score1 = 0;
	float min_score1 = 200;
	float tot_score1 = 0;
	uint32_t n_scores1 = 0;

	vector<uint64_t> time_by_concurrency;
	vector<int64_t> cpu_counters;

	//
	// Go through the CPUs and calculate the rest time for each of them
	//
	for(cpuid = 0; cpuid < num_cpus; cpuid++)
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

		if(tot_time > m_sample_length_ns)
		{
			tot_time = m_sample_length_ns;
		}

		ntr = (float)tot_time / CONCURRENCY_OBSERVATION_INTERVAL_NS;

		//
		// Extract the CPU spent while serving transactions
		//
		uint64_t tr_cpu_time;

		if(program_info != NULL)
		{
			ASSERT(program_info->m_ainfo->m_procinfo != NULL);

			int32_t nct = (int32_t)program_info->m_ainfo->m_procinfo->m_cpu_time_ns.size();

			//
			// This can happen when we drop or filter scheduler events
			//
			if(nct == 0)
			{
				return res;
			}

			ASSERT(nct == num_cpus);

			tr_cpu_time = program_info->m_ainfo->m_procinfo->m_cpu_time_ns[cpuid];
		}
		else
		{
			tr_cpu_time = cpu_state->m_lastsample_server_processes_ns;
		}

		ntrcpu = (float)tr_cpu_time * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;

		//
		// Extract the CPU spent not serving transactions
		//
		if(m_inspector->m_analyzer->has_cpu_idle_data())
		{
			idle = (static_cast<float>(m_inspector->m_analyzer->get_cpu_idle_data(cpuid)) *
			        cpu_state->m_sample_effective_length_ns) / 100;
		}
		else
		{
			idle = static_cast<float>(cpu_state->m_lastsample_idle_ns);
		}

		float otherns = (float)(cpu_state->m_sample_effective_length_ns - tr_cpu_time - idle);
		if(otherns < 0)
		{
			otherns = 0;
		}

		nother = otherns * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;

		//
		// Score calculation
		//
		if(ntr != 0)
		{
			//
			// Perform score calculation *excluding steal time*.
			// This gives us the *actual* resouce limit.
			//
			const float score =
				calculate_score_5(ntr,
			                          ntrcpu,
			                          nother,
			                          static_cast<uint32_t>(m_inspector->m_analyzer->num_server_programs()));

			tot_score += score;
			n_scores++;

			if(score > max_score)
			{
				max_score = score;
			}

			if(score < min_score)
			{
				min_score = score;
			}

			//
			// Perform score calculation *including steal time*.
			//
			float score1;

			if(m_inspector->m_analyzer->has_cpu_steal_data())
			{
				const float steal = static_cast<float>(
						m_inspector->m_analyzer->get_cpu_steal_data(cpuid));

				float ntr1 = ntr * (100 - steal) / 100;
				float nother1 = nother * (100 - steal) / 100;
				float ntrcpu1 = ntrcpu * (100 - steal) / 100;
				float idle1 = m_n_intervals_in_sample - nother1 - ntrcpu1;

				if(idle1 < 0)
				{
					idle1 = 0;
				}

				score1 = calculate_score_5(ntr1,
				                           ntrcpu1,
				                           nother1,
				                           static_cast<uint32_t>(m_inspector->m_analyzer->num_server_programs()));
			}
			else
			{
				score1 = score;
			}

			tot_score1 += score1;
			n_scores1++;

			if(score1 > max_score1)
			{
				max_score1 = score1;
			}

			if(score1 < min_score1)
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
	if(n_scores != 0 && n_scores <= n_server_threads)
	{
		//g_logger.format(sinsp_logger::SEV_DEBUG,
		//	">>%.2f-%.2f-%.2f (%" PRId32 ")",
		//	min_score,
		//	max_score,
		//	tot_score / n_scores,
		//	n_scores);
		float nost = tot_score / n_scores;
		float st = tot_score1 / n_scores1;

		res.m_current_capacity = st;
		res.m_stolen_capacity = (nost - st) / nost * 100;
	}
	else if(n_scores != 0 && n_server_threads == 1)
	{
		float nost = MIN(tot_score, 100);
		float st = MIN(tot_score1, 100);;

		res.m_current_capacity = st;
		res.m_stolen_capacity = (nost - st) / nost * 100;
	}

	return res;
}

sinsp_score_info sinsp_scores::get_process_capacity_score(sinsp_threadinfo* mainthread_info, sinsp_delays_info* delays, 
		uint32_t n_server_threads, uint64_t sample_end_time, uint64_t sample_duration)
{
	ASSERT(delays != NULL);

	sinsp_score_info res = get_system_capacity_score_bycpu_5(delays, 
		n_server_threads, 
		sample_end_time,
		sample_duration,
		mainthread_info);

	if(mainthread_info->m_ainfo->m_procinfo->m_connection_queue_usage_pct > 50)
	{
		res.m_current_capacity = MAX(res.m_current_capacity, 
			mainthread_info->m_ainfo->m_procinfo->m_connection_queue_usage_pct);
	}

	//if(res.m_current_capacity == -1)
	//{
	//	res.m_current_capacity = (float)get_system_capacity_score_global(&m_inspector->m_analyzer->m_transactions_with_cpu,
	//		n_server_threads,
	//		sample_end_time, 
	//		sample_duration);

	//	res.m_stolen_capacity = 0;
	//}

	return res;
}

#endif // HAS_ANALYZER
