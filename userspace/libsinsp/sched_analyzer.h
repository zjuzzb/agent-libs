#pragma once

class cpustate
{
public:
	cpustate();
	void init();
	inline vector<pair<int64_t, uint64_t>>::iterator find_thread(int64_t tid);
	void add_to_last_interval(int64_t tid, uint64_t delta);
	void complete_interval();

	// Each value is the pid of the process that used the most CPU during the interval
	vector<int64_t> m_time_segments;
	uint64_t m_last_switch_time;
	int64_t m_last_switch_tid;
	uint32_t m_last_time_segment;
	
	//
	// The first element in the pair is the tid, the second one is the amount of
	// time the thread has been active during the last interval
	//
	vector<pair<int64_t, uint64_t>> m_last_interval_threads;
};

class sinsp_sched_analyzer
{
public:
	sinsp_sched_analyzer(sinsp* inspector, uint32_t ncpus);

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);

	//
	// Called when the end of the sample is reached
	//
	void flush(sinsp_evt* evt, uint64_t flush_time, bool is_eof);

	//
	// Called by the engine after opening the event source and before 
	// receiving the first event. Can be used to make adjustments based on
	// the user's changes to the configuration.
	//
	void on_capture_start();

	vector<cpustate> m_cpu_states;

private:
	void update(uint64_t ts, int16_t cpu, int64_t nexttid);

	sinsp* m_inspector;
	uint32_t m_ncpus;
	uint64_t m_sample_length_ns;
};

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// V2
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
class cpustate2
{
public:
	cpustate2();
	void init();

	// Each value is the pid of the process that used the most CPU during the interval
	uint64_t m_last_switch_time;
	int64_t m_last_switch_tid;
	uint64_t m_idle_ns;
	uint64_t m_other_ns;
	uint64_t m_unknown_ns;
	uint64_t m_server_processes_ns;
	uint64_t m_lastsample_idle_ns;
	uint64_t m_lastsample_other_ns;
	uint64_t m_lastsample_unknown_ns;
	uint64_t m_lastsample_server_processes_ns;
};

class sinsp_sched_analyzer2
{
public:
	sinsp_sched_analyzer2(sinsp* inspector, uint32_t ncpus);

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);

	//
	// Called when the end of the sample is reached
	//
	void flush(sinsp_evt* evt, uint64_t flush_time, bool is_eof);

	//
	// Called by the engine after opening the event source and before 
	// receiving the first event. Can be used to make adjustments based on
	// the user's changes to the configuration.
	//
	void on_capture_start();

	vector<cpustate2> m_cpu_states;

private:
	void update(sinsp_threadinfo* tinfo, uint64_t ts, int16_t cpu, int64_t nexttid);

	sinsp* m_inspector;
	uint32_t m_ncpus;
	uint64_t m_sample_length_ns;
	uint64_t m_last_effective_sample_start;
	uint64_t m_sample_effective_length_ns;
};

