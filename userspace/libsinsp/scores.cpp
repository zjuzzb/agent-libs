#include <algorithm>
#include <stack>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer.h"
#include "scores.h"
#include "sched_analyzer.h"

sinsp_scores::sinsp_scores(sinsp* inspector, sinsp_sched_analyzer* sched_analyzer, sinsp_sched_analyzer2* sched_analyzer2)
{
	m_inspector = inspector;
	m_sched_analyzer = sched_analyzer;
	m_sched_analyzer2 = sched_analyzer2;
	m_sample_length_ns = 0;
}

int32_t sinsp_scores::get_system_capacity_score_global(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
	uint32_t n_server_threads,
	uint64_t sample_end_time, uint64_t sample_duration)
{
	uint32_t trsize = transactions->size();
	const scap_machine_info* machine_info = m_inspector->get_machine_info();
	if(machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
	}

	//
	// How the algorithm works at high level: 
	//   measure for transaction "gaps", i.e. time intervals in which no transaction
	//   is served. Sum the gaps and divide the sum by the sample time. The number
	//   is our health score, and measures the capacity that this process still has
	//   to serve transactions.
	// In practice, we use a couple of tricks:
	//   - we don't apply the algorithm to the full sample, but to the interval between the 
	//     sample start time and the end of the last transaction. After that we normalize the
	//     result as if it were a full sample. The reason is: we catch the transactions only
	//     after the next direction switch so, especially when the number of requests is very low,
	//     the last part of the sample might not contain transactions just because they are
	//     still in progress. We don't want that to skew the results.
	//   - we subdivide the sample time into intervals of CONCURRENCY_OBSERVATION_INTERVAL_NS nanoseconds,
	//     and we count the number of concurrent transactions for each interval. In other
	//     words, we "digitalize" the interval intersections, so that we never have more than
	//     (sample time / CONCURRENCY_OBSERVATION_INTERVAL_NS) of them.
	//
	if(trsize != 0)
	{
		uint64_t j;
		uint32_t k;
		uint64_t starttime = sample_end_time - sample_duration;
		uint64_t endtime = sample_end_time;
//		uint64_t endtime = m_transactions[trsize - 1].second / CONCURRENCY_OBSERVATION_INTERVAL_NS * CONCURRENCY_OBSERVATION_INTERVAL_NS; // starttime + sample_duration; 
		int64_t actual_sample_duration = (endtime > starttime)? endtime - starttime : 0;
		uint32_t concurrency;
		vector<uint64_t> time_by_concurrency;
		int64_t rest_time;

		//
		// Create the concurrency intervals vector
		//
		for(k = 0; k < MAX_HEALTH_CONCURRENCY; k++)
		{
			time_by_concurrency.push_back(0);
		}
/*
vector<uint64_t>v;
uint64_t tot = 0;
for(k = 0; k < trsize; k++)
{
	uint64_t delta = (*transactions)[k].second.first - (*transactions)[k].first;
	v.push_back(delta);
	tot += delta;
}
*/
		//
		// Make sure the transactions are ordered by start time
		//
		std::sort(transactions->begin(), transactions->end());

		//
		// Count the number of concurrent transactions for each inerval of size
		// CONCURRENCY_OBSERVATION_INTERVAL_NS.
		//
		for(j = starttime; j < endtime; j+= CONCURRENCY_OBSERVATION_INTERVAL_NS)
		{
			concurrency = 0;

			for(k = 0; k < trsize; k++)
			{
				if((*transactions)[k].first <= j)
				{
					if((*transactions)[k].second.first >= j)
					{
						concurrency++;
					}
				}
				else
				{
					break;
				}
			}

			if(concurrency < MAX_HEALTH_CONCURRENCY)
			{
				time_by_concurrency[concurrency] += CONCURRENCY_OBSERVATION_INTERVAL_NS;
			}
			else
			{
				break;
			}
		}

		//
		// Infer the rest time by subtracting the amouny of time spent at each concurrency
		// level from the sample time.
		//
		rest_time = 0;
		
		if(machine_info)
		{
			if(n_server_threads > machine_info->num_cpus)
			{
				n_server_threads = machine_info->num_cpus;
			}
		}
		else
		{
			ASSERT(false);
			return -1;
		}

		for(k = 0; k < n_server_threads; k++)
		{
			rest_time += time_by_concurrency[k];
		}

		if(actual_sample_duration != 0)
		{
			return (int32_t)(100LL - rest_time * 100 / actual_sample_duration);
		}
		else
		{
			return 100;
		}
	}

	return -1;
}

//
// The main function that takes a set of intervals, merges
// overlapping intervals and prints the result
//
void merge_intervals(vector<pair<uint64_t, uint64_t>>* intervals, OUT stack<pair<uint64_t, uint64_t>>* s, OUT uint64_t* tot_time)
{
	*tot_time = 0;

	if(intervals->size() == 0)
	{
		return;
	}

	//
    // sort the intervals based on start time
	//
    sort(intervals->begin(), intervals->end());
 
    // push the first interval to stack
    s->push((*intervals)[0]);
	*tot_time += (((*intervals)[0].second - (*intervals)[0].first));
 
	//
    // Start from the next interval and merge if necessary
	//
    for(uint32_t i = 1 ; i < intervals->size(); i++)
    {
		//
        // get interval from stack top
		//
        pair<uint64_t, uint64_t>& top = s->top();
 
		//
        // if current interval is not overlapping with stack top,
        // push it to the stack.
        // Otherwise update the ending time of top if ending of current 
        // interval is more
		//
		if(top.second < (*intervals)[i].first)
        {
            s->push((*intervals)[i]);
			*tot_time += (((*intervals)[i].second - (*intervals)[i].first));
        }
		else if(top.second < (*intervals)[i].second)
        {
			top.second = (*intervals)[i].second;
			*tot_time += (((*intervals)[i].second - top.second));
        }
    }
 
    return;
}

float sinsp_scores::get_system_capacity_score_bycpu_3(vector<vector<pair<uint64_t, uint64_t>>>* transactions, 
	uint32_t n_server_threads, 	uint64_t sample_end_time, uint64_t sample_duration)
{
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
		m_sample_length_ns = (size_t)m_inspector->m_configuration.get_analyzer_sample_length_ns();
		m_n_intervals_in_sample = (uint32_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	}

	float max_score = 0;
	float min_score = 200;
	float tot_score = 0;
	uint32_t n_scores = 0;
	vector<uint64_t> time_by_concurrency;
	vector<int64_t> cpu_counters;

	//
	// Go through the CPUs and calculate the rest time for each of them
	//
	for(cpuid = 0; cpuid < num_cpus; cpuid++)
	{
		uint32_t j;
		vector<int64_t>* cpu_vector = &m_sched_analyzer->m_cpu_states[cpuid].m_time_segments;
		float ntr = 0;
		uint32_t nother = 0;
		uint32_t ntrcpu = 0;

//vector<int64_t>v;
//int64_t tot = 0;
//for(uint32_t k = 0; k < ((*transactions)[cpuid]).size(); k++)
//{
//	int64_t delta = ((*transactions)[cpuid])[k].second - ((*transactions)[cpuid])[k].first;
//	//	int64_t delta = ((*transactions)[cpuid])[k].first - ((*transactions)[cpuid])[k-1].second;
//	v.push_back(delta);
//	if(delta >= 0)
//	{
//		tot += delta;
//	}
//	else
//	{
//		int a = 0;
//	}
//}

		stack<pair<uint64_t, uint64_t>> transaction_union;
		uint64_t tot_time;
		merge_intervals(&(*transactions)[cpuid], &transaction_union, &tot_time);
		ntr = (float)tot_time / CONCURRENCY_OBSERVATION_INTERVAL_NS;

		//
		// Claculate the CPU spent while serving transactions
		//
		for(j = 0; j < m_n_intervals_in_sample; j++)
		{
			int64_t tid = (*cpu_vector)[j];

			if(tid != 0)
			{
				sinsp_threadinfo* tinfo = m_inspector->get_thread(tid, false);
				if(tinfo != NULL)
				{
					if(tinfo->m_transaction_metrics.m_counter.m_count_in != 0)
					{
						ntrcpu++;
						continue;
					}
				}

				nother++;
			}
		}

		//
		// Perform score calculation
		//
		ntr *= m_inspector->m_analyzer->m_local_remote_ratio;

		if(ntr != 0)
		{
			float score;
			uint32_t maxcpu = MAX(m_n_intervals_in_sample / 2, m_n_intervals_in_sample - nother);
			float avail;
			if(ntrcpu != 0)
			{
				avail = MIN((float)m_n_intervals_in_sample, ntr * maxcpu / ntrcpu);
			}
			else
			{
				avail = (float)m_n_intervals_in_sample;
			}

			float maxavail = MAX(avail, ntr);
			score = ntr * 100 / maxavail;
			ASSERT(score >= 0);

			// Sometimes floating point precision causes the value to go slightly above 100
			if(score > 100)
			{
				ASSERT(score <= 101);
				score = 100;
			}

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
		}
	}

	//
	// Done scanning the transactions, return the average of the CPU rest times.
	// NOTE: if the number of scores (= number of processors that have been 
	//       serving transactions) is smaller than the number of *threads* that 
	//       have been serving transactions, it means that we have one or servers 
	//       that are floating across CPUs. In that case, our number would not have 
	//       sense and we return -1, so the global health score will be used.
	//
	if(n_scores != 0 && n_scores <= n_server_threads)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
			">>%.2f-%.2f-%.2f (%" PRId32 ")",
			min_score,
			max_score,
			tot_score / n_scores,
			n_scores);

		return (tot_score / n_scores);
	}
	else
	{
		return -1;
	}

	return -1;
}

float sinsp_scores::get_system_capacity_score_bycpu_4(vector<vector<pair<uint64_t, uint64_t>>>* transactions, 
	uint32_t n_server_threads, 	uint64_t sample_end_time, uint64_t sample_duration)
{
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
		m_sample_length_ns = (size_t)m_inspector->m_configuration.get_analyzer_sample_length_ns();
		m_n_intervals_in_sample = (uint32_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	}

	float max_score = 0;
	float min_score = 200;
	float tot_score = 0;
	uint32_t n_scores = 0;
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

		stack<pair<uint64_t, uint64_t>> transaction_union;
		uint64_t tot_time;
		merge_intervals(&(*transactions)[cpuid], &transaction_union, &tot_time);
		ntr = (float)tot_time / CONCURRENCY_OBSERVATION_INTERVAL_NS;

		//
		// Extract the CPU spent while serving transactions
		//
		ntrcpu = (float)cpu_state->m_lastsample_server_processes_ns * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;
		float idle;
		if(m_inspector->m_analyzer->m_cpu_idles.size() != 0)
		{
			ASSERT(m_inspector->m_analyzer->m_cpu_idles.size() == num_cpus);

			idle = (((float)m_inspector->m_analyzer->m_cpu_idles[cpuid]) * cpu_state->m_sample_effective_length_ns) / 100;
		}
		else
		{
//			g_logger.format(sinsp_logger::SEV_WARNING, "no idle information, can't calculate capacity score");
//			return -1;
			idle = (float)cpu_state->m_lastsample_idle_ns;
		}

		float otherns = (float)(cpu_state->m_sample_effective_length_ns - cpu_state->m_lastsample_server_processes_ns - idle);
		if(otherns < 0)
		{
			otherns = 0;
		}

		nother = otherns * (float)m_n_intervals_in_sample / cpu_state->m_sample_effective_length_ns;

		//
		// Perform score calculation
		//
		ntr *= m_inspector->m_analyzer->m_local_remote_ratio;

		if(ntr != 0)
		{
			float score;
			float fnintervals = (float)m_n_intervals_in_sample;

			float maxcpu = MAX(fnintervals / 2, fnintervals - nother);
			float avail;
			if(ntrcpu != 0)
			{
				avail = MIN(fnintervals, ntr * maxcpu / ntrcpu);
			}
			else
			{
				avail = fnintervals;
			}

			float maxavail = MAX(avail, ntr);
			score = ntr * 100 / maxavail;
			ASSERT(score >= 0);

			// Sometimes floating point precision causes the value to go slightly above 100
			if(score > 100)
			{
				ASSERT(score <= 101);
				score = 100;
			}

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
		}
	}

	//
	// Done scanning the transactions, return the average of the CPU rest times.
	// NOTE: if the number of scores (= number of processors that have been 
	//       serving transactions) is smaller than the number of *threads* that 
	//       have been serving transactions, it means that we have one or servers 
	//       that are floating across CPUs. In that case, our number would not have 
	//       sense and we return -1, so the global health score will be used.
	//
	if(n_scores != 0 && n_scores <= n_server_threads)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG,
			">>%.2f-%.2f-%.2f (%" PRId32 ")",
			min_score,
			max_score,
			tot_score / n_scores,
			n_scores);

		return (tot_score / n_scores);
	}
	else
	{
		return -1;
	}

	return -1;
}

/*
int32_t sinsp_scores::get_system_capacity_score_bycpu(vector<vector<pair<uint64_t, uint64_t>>>* transactions, 
	uint32_t n_server_threads,
	uint64_t sample_end_time, uint64_t sample_duration)
{
	int32_t cpuid;
	const scap_machine_info* machine_info = m_inspector->get_machine_info();
	if(machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
	}
	int32_t num_cpus = machine_info->num_cpus;

	if(m_sample_length_ns == 0)
	{
		m_sample_length_ns = (size_t)m_inspector->m_configuration.get_analyzer_sample_length_ns();
		m_n_intervals_in_sample = (uint32_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	}

	//if(m_cpu_transaction_vectors.size() == 0)
	//{
	//	m_cpu_transaction_vectors = vector<vector<uint8_t>>(num_cpus);
	//	for(cpuid = 0; cpuid < num_cpus; cpuid++)
	//	{
	//		m_cpu_transaction_vectors[cpuid].insert(m_cpu_transaction_vectors[cpuid].begin(), 
	//			m_n_intervals_in_sample, 
	//			0);
	//	}
	//}

	int32_t max_score = 0;
	int32_t min_score = 200;
	int32_t tot_score = 0;
	int32_t n_scores = 0;

	if(num_cpus != 0)
	{
		vector<uint64_t> time_by_concurrency;
		uint32_t k;
		vector<int64_t> cpu_counters;
		uint64_t starttime = sample_end_time - sample_duration;

		//
		// Go through the CPUs and calculate the rest time for each of them
		//
		for(cpuid = 0; cpuid < num_cpus; cpuid++)
		{
			uint32_t j;
			uint32_t trsize = (*transactions)[cpuid].size();
			vector<int64_t>* cpu_vector = &m_sched_analyzer->m_cpu_states[cpuid].m_time_segments;
			uint64_t intervaltime;
			uint32_t ntr = 0;
			uint32_t nother = 0;
			uint32_t ntrcpu = 0;

//((*transactions)[cpuid]).clear();
//((*transactions)[cpuid]).push_back(pair<uint64_t, uint64_t>(1, 3));
//((*transactions)[cpuid]).push_back(pair<uint64_t, uint64_t>(3, 7));
//((*transactions)[cpuid]).push_back(pair<uint64_t, uint64_t>(8, 10));
//((*transactions)[cpuid]).push_back(pair<uint64_t, uint64_t>(11, 13));
//
//vector<int64_t>v;
//int64_t tot = 0;
//for(k = 0; k < ((*transactions)[cpuid]).size(); k++)
//{
//	int64_t delta = ((*transactions)[cpuid])[k].second - ((*transactions)[cpuid])[k].first;
////	int64_t delta = ((*transactions)[cpuid])[k].first - ((*transactions)[cpuid])[k-1].second;
//	v.push_back(delta);
//	if(delta >= 0)
//	{
//		tot += delta;
//	}
//	else
//	{
//		int a = 0;
//	}
//}

			stack<pair<uint64_t, uint64_t>> transaction_union;
			uint64_t tot_time;
			merge_intervals(&(*transactions)[cpuid], &transaction_union, &tot_time);

			//
			// Make sure the transactions are ordered by start time
			//
			std::sort(((*transactions)[cpuid]).begin(), ((*transactions)[cpuid]).end());

			//
			// Count the number of concurrent transactions for each inerval of size
			// CONCURRENCY_OBSERVATION_INTERVAL_NS.
			//
			for(j = 0; j < m_n_intervals_in_sample; j++)
			{
				intervaltime = starttime + j * CONCURRENCY_OBSERVATION_INTERVAL_NS;

				for(k = 0; k < trsize; k++)
				{
					if((*transactions)[cpuid][k].first <= intervaltime)
					{
						if((*transactions)[cpuid][k].second >= (intervaltime - CONCURRENCY_OBSERVATION_INTERVAL_NS))
						{
							ntr++;
							break;
						}
					}
					else
					{
						break;
					}
				}

				int64_t tid = (*cpu_vector)[j];

				if(tid != 0)
				{
					sinsp_threadinfo* tinfo = m_inspector->get_thread(tid, false);
					if(tinfo != NULL)
					{
						if(tinfo->m_transaction_metrics.m_counter.m_count_in != 0)
						{
							ntrcpu++;
							continue;
						}
					}

					nother++;
				}
			}

			int32_t score;

			if(ntr != 0 && ntrcpu != 0)
			{
				uint32_t maxcpu = MAX(m_n_intervals_in_sample / 2, m_n_intervals_in_sample - nother);
				uint32_t avail = MIN(m_n_intervals_in_sample, ntr * maxcpu / ntrcpu);
				uint32_t maxavail = MAX(avail, ntr);
				score = 100 - ntr * 100 / maxavail;
//sort(cpu_vector->begin(), cpu_vector->end());
				ASSERT(score >= 0);
				ASSERT(score <= 100);

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
			}
		}

		//
		// Done scanning the transactions, return the average of the CPU rest times
		//
		if(n_scores != 0)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG,
				">>%" PRId32"-%" PRId32"-%" PRId32"(%" PRId32 ")",
				min_score,
				max_score,
				tot_score / n_scores,
				n_scores);

			return (tot_score / n_scores);
		}
		else
		{
			return -1;
		}
	}

	return -1;
}

int32_t sinsp_scores::get_system_capacity_score_bycpu_old(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
	uint32_t n_server_threads,
	uint64_t sample_end_time, uint64_t sample_duration)
{
	uint32_t trsize = transactions->size();
	int32_t cpuid;
	const scap_machine_info* machine_info = m_inspector->get_machine_info();
	if(machine_info == NULL)
	{
		ASSERT(false);
		throw sinsp_exception("no machine information. Scores calculator can't be initialized.");
	}
	int32_t num_cpus = machine_info->num_cpus;

	if(trsize != 0 && num_cpus != 0)
	{
		vector<uint64_t> time_by_concurrency;
		uint32_t k;
		vector<int64_t> cpu_counters;
		uint64_t starttime = sample_end_time - sample_duration;
		uint64_t endtime = sample_end_time;
		int64_t actual_sample_duration = (endtime > starttime)? endtime - starttime : 0;

		//
		// If the number of *processors* that served transactions is smaller than the number of
		// *processes* that served transactions, it means that the processes were shuffled 
		// around the CPUs. In that case, don't do the calculation (it would be meaningless)
		// and just return -1. The analyzer will take care of using a fallback algorithm.
		//
		for(cpuid = 0; cpuid < num_cpus; cpuid++)
		{
			cpu_counters.push_back(0);
		}

		for(k = 0; k < trsize; k++)
		{
			ASSERT((*transactions)[k].second.second < num_cpus);

			cpu_counters[(*transactions)[k].second.second]++;
		}

		for(cpuid = 0, k = 0; cpuid < num_cpus; cpuid++)
		{
			if(cpu_counters[cpuid] != 0)
			{
				k++;
			}
		}

		if(n_server_threads < k)
		{
			return -1;
		}

		//
		// Create the concurrency intervals vector
		//
		for(k = 0; k < MAX_HEALTH_CONCURRENCY; k++)
		{
			time_by_concurrency.push_back(0);
		}

		//
		// Make sure the transactions are ordered by start time
		//
		std::sort(transactions->begin(), transactions->end());

		//
		// Go through the CPUs and calculate the rest time for each of them
		//
		for(cpuid = 0; cpuid < num_cpus; cpuid++)
		{
			uint64_t j;
			uint32_t concurrency;

			//
			// Count the number of concurrent transactions for each inerval of size
			// CONCURRENCY_OBSERVATION_INTERVAL_NS.
			//
			for(j = starttime; j < endtime; j+= CONCURRENCY_OBSERVATION_INTERVAL_NS)
			{
				concurrency = 0;

				for(k = 0; k < trsize; k++)
				{
					if((*transactions)[k].first <= (j + CONCURRENCY_OBSERVATION_INTERVAL_NS))
					{
						if((*transactions)[k].second.second == cpuid)
						{
							if((*transactions)[k].second.first >= (j - CONCURRENCY_OBSERVATION_INTERVAL_NS))
							{
								concurrency++;
							}
						}
					}
					else
					{
						break;
					}
				}

				//
				// If this is a transaction-free interval, make sure it's not a time slot that has been
				// stolen by another process that is loading the cpu.
				//

				if(concurrency < MAX_HEALTH_CONCURRENCY)
				{
					time_by_concurrency[concurrency] += CONCURRENCY_OBSERVATION_INTERVAL_NS;
				}
				else
				{
					break;
				}
			}

			//
			// Save the rest time
			//
			cpu_counters[cpuid] = time_by_concurrency[0];

			//
			// Clean the concurrency intervals vector so we're ready for the next CPU
			//
			if(cpuid < num_cpus)
			{
				for(k = 0; k < MAX_HEALTH_CONCURRENCY; k++)
				{
					time_by_concurrency[k] = 0;
				}
			}
		}

		//
		// Done scanning the transactions, return the average of the CPU rest times
		//
		if(actual_sample_duration != 0)
		{
			int64_t minresttime = 1000000000;
			int64_t maxresttime = 0;
			int64_t avgresttime = 0;
			int32_t n_active_cpus = 0;

			for(cpuid = 0; cpuid < num_cpus; cpuid++)
			{
				int64_t val = cpu_counters[cpuid];

				if(val != 1000000000)
				{
					n_active_cpus++;

					avgresttime += val;

					if(val < minresttime)
					{
						minresttime = val;
					}

					if(val > maxresttime)
					{
						maxresttime = val;
					}
				}
			}
			
			if(n_active_cpus)
			{
				avgresttime /= n_active_cpus;

				g_logger.format(sinsp_logger::SEV_DEBUG,
					">>%" PRId32"-%" PRId32"-%" PRId32"(%" PRId32 ")",
					(int32_t)(minresttime * 100 / actual_sample_duration),
					(int32_t)(maxresttime * 100 / actual_sample_duration),
					(int32_t)(avgresttime * 100 / actual_sample_duration),
					n_active_cpus);

				return (int32_t)(avgresttime * 100 / actual_sample_duration);				
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}

	return -1;
}
*/

float sinsp_scores::get_process_capacity_score(float system_capacity_score, sinsp_threadinfo* mainthread_info)
{
	float res = -1;
	float local_remote_ratio;

	if(system_capacity_score == -1)
	{
		return res;
	}

	//
	// Make sure this is the main process thread
	//
	if(!mainthread_info->is_main_thread() ||
		mainthread_info->m_procinfo == NULL)
	{
		ASSERT(false);
		return res;
	}

	//
	// Health score is currently calculated only for server processes only 
	//
	if(mainthread_info->m_procinfo->m_proc_transaction_metrics.m_counter.m_count_in == 0)
	{
		return res;
	}

	res = system_capacity_score;

	//
	// Take the system health score and normalize it using the local/remote ratios
	//
	if(mainthread_info->m_procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_in != (uint64_t)0)
	{
		local_remote_ratio = (float)mainthread_info->m_procinfo->m_proc_transaction_processing_delay_ns / 
			(float)mainthread_info->m_procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_in;

		res = system_capacity_score * local_remote_ratio / m_inspector->m_analyzer->m_local_remote_ratio;
		if(res > 100)
		{
			res = 100;
		}
	}

/*
	if(mainthread_info->m_connection_queue_usage_pct > 30)
	{
		res = MIN(res, 100 - mainthread_info->m_connection_queue_usage_pct);
	}

	if(mainthread_info->m_fd_usage_pct > 30)
	{
		res = MIN(res, 100 - mainthread_info->m_fd_usage_pct);
	}
*/
	return res;
}
