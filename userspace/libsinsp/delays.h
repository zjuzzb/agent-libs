#pragma once

//
// The main analyzer class
//
class sinsp_delays
{
public:
	sinsp_delays(sinsp_analyzer* analyzer);
	uint64_t compute_thread_transaction_delay(sinsp_transaction_counters* trcounters);
	void compute_host_transaction_delay(sinsp_transaction_counters* counters);
	static void merge_intervals(vector<sinsp_trlist_entry>* intervals, OUT stack<sinsp_trlist_entry>* s, OUT uint64_t* tot_time, int64_t progid);

private:
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
};
