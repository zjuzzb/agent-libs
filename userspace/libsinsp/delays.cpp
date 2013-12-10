#include <algorithm>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer.h"
#include "delays.h"

sinsp_delays::sinsp_delays(sinsp_analyzer* analyzer)
{
	ASSERT(analyzer);
	m_analyzer = analyzer;
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
