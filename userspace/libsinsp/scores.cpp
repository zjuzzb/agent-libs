#include <algorithm>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "scores.h"

sinsp_scores::sinsp_scores(sinsp* inspector)
{
	m_inspector = inspector;
}

int32_t sinsp_scores::get_system_health_score_global(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
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

vector<uint64_t>v;
uint64_t tot = 0;
for(k = 0; k < trsize; k++)
{
	uint64_t delta = (*transactions)[k].second.first - (*transactions)[k].first;
	v.push_back(delta);
	tot += delta;
}

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
			return (int32_t)(rest_time * 100 / actual_sample_duration);
		}
		else
		{
			return 0;
		}
	}

	return -1;
}

int32_t sinsp_scores::get_system_health_score_bycpu(vector<pair<uint64_t,pair<uint64_t, uint16_t>>>* transactions, 
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
int aa = 0;
			//
			// Count the number of concurrent transactions for each inerval of size
			// CONCURRENCY_OBSERVATION_INTERVAL_NS.
			//
			for(j = starttime; j < endtime; j+= CONCURRENCY_OBSERVATION_INTERVAL_NS)
			{
				concurrency = 0;

if(j - starttime == 15 * CONCURRENCY_OBSERVATION_INTERVAL_NS)
{
	int a = 0;
}
				for(k = 0; k < trsize; k++)
				{
if(k == 28)
{
	int a = 0;
}
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

if(concurrency == 0)
{
	aa++;
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

int32_t sinsp_scores::get_process_health_score(int32_t system_health_score, sinsp_threadinfo* mainthread_info)
{
	uint32_t res = -1;

	if(system_health_score == -1)
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
	if(mainthread_info->m_transaction_metrics.m_counter.m_count_in == 0)
	{
		return res;
	}

	res = system_health_score;

	if(mainthread_info->m_connection_queue_usage_pct > 30)
	{
		res = MIN(res, 100 - mainthread_info->m_connection_queue_usage_pct);
	}

	if(mainthread_info->m_fd_usage_pct > 30)
	{
		res = MIN(res, 100 - mainthread_info->m_fd_usage_pct);
	}

	return res;
}
