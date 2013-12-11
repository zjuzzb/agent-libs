#include <algorithm>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer.h"
#include "delays.h"

sinsp_delays::sinsp_delays(sinsp_analyzer* analyzer, uint32_t ncpus)
{
	ASSERT(analyzer);
	m_analyzer = analyzer;
	m_num_cpus = ncpus;
	m_last_prog_delays.m_last_prog_delays = vector<sinsp_program_percpu_delays>(ncpus);
}

//
// Based on the transaction counters for this process, calculate the delay in trasanction 
// handling that the process introduces
//
uint64_t sinsp_delays::compute_thread_transaction_delay(sinsp_transaction_counters* trcounters)
{
	if(trcounters->m_counter.m_count_in == 0)
	{
		//
		// This is not a server
		//
		return 0;
	}
	else
	{
		ASSERT(trcounters->m_counter.m_time_ns_in != 0);

		int64_t res =  trcounters->m_counter.m_time_ns_in - trcounters->m_counter.m_time_ns_out;

		if(res <= 0)
		{
			return 0;
		}
		else
		{
			return res;
		}
	}
}

void sinsp_delays::compute_host_transaction_delay(sinsp_transaction_counters* counters)
{
	ASSERT(m_analyzer != NULL);

	if(counters->m_counter.m_count_in == 0)
	{
		//
		// This host is not serving transactions
		//
		m_analyzer->m_host_transaction_delay_ns = -1;
	}
	else
	{
		ASSERT(counters->m_counter.m_time_ns_in != 0);

		if(m_analyzer->m_client_tr_time_by_servers == 0)
		{
			//
			// No outbound connections made by servers: it means that This node is a
			// leaf in the connection tree and the host_transaction_delay euqals to the
			// input transaction processing time.
			//
			m_analyzer->m_host_transaction_delay_ns = counters->m_counter.m_time_ns_in;
			return;
		}

		int64_t res = counters->m_counter.m_time_ns_in - m_analyzer->m_client_tr_time_by_servers;

		if(res <= 0)
		{
			m_analyzer->m_host_transaction_delay_ns = 0;
		}
		else
		{
			m_analyzer->m_host_transaction_delay_ns = res;
		}
	}
}

//
// helper function that takes a set of transactions and merges them.
// progid can be used to filter on a specific program id. progid=-1 means accept all the transactions.
// Returns the sum of the time of the merged transactions.
//
uint64_t sinsp_delays::merge_transactions(vector<sinsp_trlist_entry>* intervals, OUT vector<sinsp_trlist_entry>* s)
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
			s->push_back((*intervals)[i]);
			tot_time += (((*intervals)[i].m_etime - (*intervals)[i].m_stime));

			initializing = false;
		}

		//
        // get interval from stack top
		//
        sinsp_trlist_entry& top = s->back();
 
		//
        // if current interval is not overlapping with stack top,
        // push it to the stack.
        // Otherwise update the ending time of top if ending of current 
        // interval is more
		//
		if(top.m_etime < (*intervals)[i].m_stime)
        {
            s->push_back((*intervals)[i]);
			tot_time += (((*intervals)[i].m_etime - (*intervals)[i].m_stime));
        }
		else if(top.m_etime < (*intervals)[i].m_etime)
        {
			top.m_etime = (*intervals)[i].m_etime;
			tot_time += (((*intervals)[i].m_etime - top.m_etime));
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
		vector<sinsp_trlist_entry>* trs = &client_transactions_per_cpu->at(j);
		vector<sinsp_trlist_entry>::iterator client_iter;

		//
		// sort the intervals based on start time
		//
		sort(trs->begin(), trs->end(), sinsp_trlist_entry_comparer());

		//
		// cycle through the client transactions
		//
		bool filter = true;

		for(client_iter = trs->begin(); client_iter != trs->end(); trs++)
		{
			for(k = 0; k < ncpus; k++)
			{
				while(true)
				{
					if(server_iters[k] == server_iters[k] != server_transactions_per_cpu->at(j).end())
					
					if(client_iter->m_stime > server_iters[k]->m_stime)
					{
						if(client_iter->m_etime < server_iters[k]->m_etime)
						{
							filter = false;
							break;
						}
					}

					++server_iters[k];
				}
			}
		}
	}

	return tot_time;
}

/*
					else
					{
						while(true)
						{
							++server_iters[k];

							if(client_iter->m_stime <= server_iters[k]->m_stime) 
							{
							}
								&& (server_iters[k] != server_transactions_per_cpu->at(j).end()))
						}
					}
*/

void sinsp_delays::compute_program_cpu_delays(sinsp_threadinfo* program_info, int32_t cpuid)
{
	sinsp_program_percpu_delays* pd = &m_last_prog_delays.m_last_prog_delays[cpuid];

	pd->clear();

	ASSERT(m_analyzer != NULL);

	pd->m_total_merged_inbound_delay = sinsp_delays::merge_transactions(&(program_info->m_procinfo->m_server_transactions_per_cpu[cpuid]),
		&pd->m_last_inbound_transaction_union);
}

sinsp_program_delays* sinsp_delays::compute_program_delays(sinsp_threadinfo* program_info)
{
	int32_t j;

	//
	// Per CPU transaction merging
	//
	for(j = 0; j < m_num_cpus; j++)
	{
		compute_program_cpu_delays(program_info, j);
	}

	//
	//
	//
	prune_client_transactions(&program_info->m_procinfo->m_client_transactions_per_cpu,
		&program_info->m_procinfo->m_server_transactions_per_cpu);

	//
	// Local transaction processing delay
	//
	m_last_prog_delays.m_transaction_processing_delay_ns = compute_thread_transaction_delay(&program_info->m_procinfo->m_proc_transaction_metrics);

	//
	// Ratio between inbound transaction time and local processing time
	//
	m_last_prog_delays.m_local_remote_ratio = 1;
	int64_t proc_transaction_processing_delay_ns = m_last_prog_delays.m_transaction_processing_delay_ns;
	uint64_t time_ns_in = program_info->m_procinfo->m_proc_transaction_metrics.m_counter.m_time_ns_in;

	if(proc_transaction_processing_delay_ns != -1LL)
	{
		if(time_ns_in != 0)
		{
			m_last_prog_delays.m_local_remote_ratio = (float)proc_transaction_processing_delay_ns / 
				(float)time_ns_in;
		}
	}

	return &m_last_prog_delays;
}
