#include <algorithm>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_ANALYZER
#include "analyzer_int.h"
#include "analyzer.h"
#include "connectinfo.h"
#include "delays.h"
#include "analyzer_thread.h"

sinsp_delays::sinsp_delays(sinsp_analyzer* analyzer, uint32_t ncpus)
{
	ASSERT(analyzer);
	m_analyzer = analyzer;
	m_num_cpus = ncpus;
}

//
// helper function that takes a set of transactions and merges them.
// progid can be used to filter on a specific program id. progid=-1 means accept all the transactions.
// Returns the sum of the time of the merged transactions.
//
uint64_t sinsp_delays::merge_transactions(vector<sinsp_trlist_entry>* intervals, OUT vector<sinsp_trlist_entry>* merge)
{
	uint64_t tot_time = 0;
	bool initializing = true;
	uint32_t size = intervals->size();

	if(size == 0)
	{
		return 0;
	}

	//
    // sort the intervals based on start time
	//
    sort(intervals->begin(), intervals->end(), sinsp_trlist_entry_comparer());
 
	//
    // Start from the next interval and merge if necessary
	//
    for(uint32_t i = 0 ; i < size; i++)
    {
		if((*intervals)[i].m_flags & sinsp_trlist_entry::FL_FILTERED_OUT)
		{
			continue;
		}

		if(initializing)
		{
			// push the first interval to the stack
			merge->push_back((*intervals)[i]);
			tot_time += (((*intervals)[i].m_etime - (*intervals)[i].m_stime));

			initializing = false;
		}

		//
        // get interval from stack top
		//
        sinsp_trlist_entry& top = merge->back();
 
		//
        // if current interval is not overlapping with stack top,
        // push it to the stack.
        // Otherwise update the ending time of top if ending of current 
        // interval is more
		//
		if(top.m_etime < (*intervals)[i].m_stime)
        {
            merge->push_back((*intervals)[i]);
			tot_time += (((*intervals)[i].m_etime - (*intervals)[i].m_stime));
        }
		else if(top.m_etime < (*intervals)[i].m_etime)
        {
			tot_time += (((*intervals)[i].m_etime - top.m_etime));
			top.m_etime = (*intervals)[i].m_etime;
        }
    }
 
    return tot_time;
}

//
// helper function that removes the outbound transactions that are not contained inside any inbound transaction
//
uint64_t sinsp_delays::prune_client_transactions(vector<vector<sinsp_trlist_entry>>* client_transactions_per_cpu, 
	vector<vector<sinsp_trlist_entry>>* server_transactions_per_cpu)
{
	uint32_t j, k;
	uint64_t tot_time = 0;
	uint32_t ncpus = client_transactions_per_cpu->size();
	vector<uint32_t> procpos;
	vector<vector<sinsp_trlist_entry>::iterator> server_iters = vector<vector<sinsp_trlist_entry>::iterator>(ncpus);
	vector<sinsp_trlist_entry>::iterator ppit;

	if(ncpus == 0)
	{
		return 0;
	}

	for(j = 0; j < ncpus; j++)
	{
		server_iters[j] = server_transactions_per_cpu->at(j).begin();
	}

	//
	// Go through the different CPUs
	//
	for(j = 0; j < ncpus; j++)
	{
		vector<sinsp_trlist_entry>* client_trs = &client_transactions_per_cpu->at(j);
		vector<sinsp_trlist_entry>::iterator client_iter;

		//
		// sort the intervals based on start time
		//
		sort(client_trs->begin(), client_trs->end(), sinsp_trlist_entry_comparer());

		//
		// cycle through the client transactions
		//
		for(client_iter = client_trs->begin(); client_iter != client_trs->end(); client_iter++)
		{
			bool filter_out = true;

			//
			// Go through the server transactions and find a containing one
			//
			for(k = 0; k < ncpus; k++)
			{
				while(true)
				{
					if(server_iters[k] == server_transactions_per_cpu->at(k).end())
					{
						break;
					}
					
					if(client_iter->m_stime > server_iters[k]->m_stime)
					{
						if(client_iter->m_etime < server_iters[k]->m_etime)
						{
							filter_out = false;
							break;
						}
					}
					else
					{
						break;
					}

					++server_iters[k];
				}
			}

			if(filter_out == true)
			{
				client_iter->m_flags |= sinsp_trlist_entry::FL_FILTERED_OUT;
			}
		}
	}

	return tot_time;
}

void sinsp_delays::compute_program_percpu_delays(sinsp_threadinfo* program_info, int32_t cpuid, sinsp_delays_info* delays)
{
	sinsp_percpu_delays* pd = &delays->m_last_percpu_delays[cpuid];

	pd->clear();

	ASSERT(m_analyzer != NULL);

	//
	// Merge the server transactions
	//
	pd->m_merged_server_delay = sinsp_delays::merge_transactions(&(program_info->m_ainfo->m_procinfo->m_server_transactions_per_cpu[cpuid]),
		&pd->m_last_server_transaction_union);

	//
	// Merge the client transactions
	//
	pd->m_merged_client_delay = sinsp_delays::merge_transactions(&(program_info->m_ainfo->m_procinfo->m_client_transactions_per_cpu[cpuid]),
		&pd->m_last_client_transaction_union);

	//
	// Add the just computed delays to the program ones
	//
	delays->m_merged_server_delay += pd->m_merged_server_delay;
	delays->m_merged_client_delay += pd->m_merged_client_delay;

	//
	// Copy the external transactions to the host list
	//
	vector<sinsp_trlist_entry>::iterator it;

	for(it = program_info->m_ainfo->m_procinfo->m_server_transactions_per_cpu[cpuid].begin();
		it != program_info->m_ainfo->m_procinfo->m_server_transactions_per_cpu[cpuid].end();
		it ++)
	{
		ASSERT(m_analyzer != NULL);

		if((it->m_flags & sinsp_trlist_entry::FL_EXTERNAL) && !(it->m_flags & sinsp_trlist_entry::FL_FILTERED_OUT))
		{
			m_analyzer->m_host_server_transactions[cpuid].push_back(*it);
		}
	}

	for(it = program_info->m_ainfo->m_procinfo->m_client_transactions_per_cpu[cpuid].begin();
		it != program_info->m_ainfo->m_procinfo->m_client_transactions_per_cpu[cpuid].end();
		it ++)
	{
		ASSERT(m_analyzer != NULL);

		if((it->m_flags & sinsp_trlist_entry::FL_EXTERNAL) && !(it->m_flags & sinsp_trlist_entry::FL_FILTERED_OUT))
		{
			m_analyzer->m_host_client_transactions[cpuid].push_back(*it);
		}
	}
}

void sinsp_delays::compute_program_delays(sinsp_threadinfo* program_info, OUT sinsp_delays_info* delays)
{
	int32_t j;

	delays->m_local_processing_delay_ns = -1;

	if(program_info->m_ainfo->m_procinfo->m_proc_transaction_metrics.m_counter.m_count_in == 0)
	{
		//
		// Not a server
		//
		return;
	}

	if(delays->m_last_percpu_delays.size() == 0)
	{
		ASSERT(m_num_cpus != 0);
		delays->m_last_percpu_delays = vector<sinsp_percpu_delays>(m_num_cpus);
	}

	delays->clear();

	//
	// Prune the client connections
	//
	prune_client_transactions(&program_info->m_ainfo->m_procinfo->m_client_transactions_per_cpu,
		&program_info->m_ainfo->m_procinfo->m_server_transactions_per_cpu);

	//
	// Per CPU transaction merging
	//
	for(j = 0; j < m_num_cpus; j++)
	{
		compute_program_percpu_delays(program_info, j, delays);
	}

	//
	// Local transaction processing delay
	//
	delays->m_local_processing_delay_ns = 
		(int64_t)(delays->m_merged_server_delay - delays->m_merged_client_delay);

	ASSERT(delays->m_local_processing_delay_ns >= 0);

	//
	// Ratio between inbound transaction time and local processing time
	//
	if(delays->m_merged_server_delay != 0)
	{
		delays->m_local_remote_ratio = 
			((double)delays->m_local_processing_delay_ns) / delays->m_merged_server_delay;
	}
	else
	{
		delays->m_local_remote_ratio = 1;
		if(delays->m_merged_server_delay != 0 || delays->m_merged_client_delay == 0)
		{
			ASSERT(false);
			delays->m_local_processing_delay_ns = -1;
		}
	}

	return;
}

void sinsp_delays::compute_host_percpu_delays(int32_t cpuid, sinsp_delays_info* delays)
{
	sinsp_percpu_delays* pd = &delays->m_last_percpu_delays[cpuid];

	pd->clear();

	ASSERT(m_analyzer != NULL);

//vector<vector<sinsp_trlist_entry>>* transactions = &m_analyzer->m_host_server_transactions;
//vector<int64_t>v;
//int64_t tot = 0;
//for(uint32_t k = 0; k < ((*transactions)[cpuid]).size(); k++)
//{
//	((*transactions)[cpuid])[k].m_stime -= 1387826258000000000;
//	((*transactions)[cpuid])[k].m_etime -= 1387826258000000000;
//	int64_t delta = ((*transactions)[cpuid])[k].m_etime - ((*transactions)[cpuid])[k].m_stime;
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

	//
	// Merge the server transactions
	//
	pd->m_merged_server_delay = sinsp_delays::merge_transactions(&(m_analyzer->m_host_server_transactions[cpuid]),
		&pd->m_last_server_transaction_union);

	//
	// Merge the client transactions
	//
	pd->m_merged_client_delay = sinsp_delays::merge_transactions(&(m_analyzer->m_host_client_transactions[cpuid]),
		&pd->m_last_client_transaction_union);

	//
	// Add the just computed delays to the program ones
	//
	delays->m_merged_server_delay += pd->m_merged_server_delay;
	delays->m_merged_client_delay += pd->m_merged_client_delay;
}

void sinsp_delays::compute_host_delays(OUT sinsp_delays_info* delays)
{
	int32_t j;

	delays->m_local_processing_delay_ns = -1;

	if(m_analyzer->m_host_transaction_counters.m_counter.m_count_in == 0)
	{
		//
		// Not a server
		//
		return;
	}

	if(delays->m_last_percpu_delays.size() == 0)
	{
		ASSERT(m_num_cpus != 0);
		delays->m_last_percpu_delays = vector<sinsp_percpu_delays>(m_num_cpus);
	}

	delays->clear();

	//
	// Per CPU transaction merging
	//
	for(j = 0; j < m_num_cpus; j++)
	{
		compute_host_percpu_delays(j, delays);
	}

	//
	// Local transaction processing delay
	//
	delays->m_local_processing_delay_ns = 
		(int64_t)(delays->m_merged_server_delay - delays->m_merged_client_delay);

	if(delays->m_local_processing_delay_ns < 0)
	{
//		ASSERT(false);
		delays->m_local_processing_delay_ns = -1;
	}

	return;
}

#endif // HAS_ANALYZER
