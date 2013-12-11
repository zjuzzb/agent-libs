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
//
void sinsp_delays::merge_intervals(vector<sinsp_trlist_entry>* intervals, OUT vector<sinsp_trlist_entry>* s, OUT uint64_t* tot_time, int64_t progid)
{
	*tot_time = 0;
	bool initializing = true;

	if(intervals->size() == 0)
	{
		return;
	}

	//
    // sort the intervals based on start time
	//
    sort(intervals->begin(), intervals->end(), sinsp_trlist_entry_comparer());
 
	//
    // Start from the next interval and merge if necessary
	//
    for(uint32_t i = 0 ; i < intervals->size(); i++)
    {
		if(progid != -1LL)
		{
			if((*intervals)[i].m_progid != progid)
			{
				continue;
			}
		}

		if(initializing)
		{
			// push the first interval to the stack
			s->push_back((*intervals)[i]);
			*tot_time += (((*intervals)[i].m_etime - (*intervals)[i].m_stime));

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
			*tot_time += (((*intervals)[i].m_etime - (*intervals)[i].m_stime));
        }
		else if(top.m_etime < (*intervals)[i].m_etime)
        {
			top.m_etime = (*intervals)[i].m_etime;
			*tot_time += (((*intervals)[i].m_etime - top.m_etime));
        }
    }
 
    return;
}

void sinsp_delays::compute_program_cpu_delays(sinsp_threadinfo* program_info, int32_t cpuid)
{
	sinsp_program_percpu_delays* pd = &m_last_prog_delays.m_last_prog_delays[cpuid];

	pd->clear();

	ASSERT(m_analyzer != NULL);

	sinsp_delays::merge_intervals(&(m_analyzer->m_server_transactions_per_cpu[cpuid]),
		&pd->m_last_inbound_transaction_union, 
		&pd->m_total_merged_inbound_delay, 
		(program_info)? program_info->m_pid : -1LL);
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
