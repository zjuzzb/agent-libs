#pragma once

#include "analyzer_thread_type.h"

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
	uint64_t m_last_effective_sample_start;
	uint64_t m_sample_effective_length_ns;
	uint64_t m_last_flush_time;
};

class sinsp_sched_analyzer2
{
public:
	sinsp_sched_analyzer2(sinsp_analyzer& analyzer, sinsp* inspector, uint32_t ncpus);

	//
	// Processing entry point
	//
	void process_event(sinsp_evt* evt);

	//
	// Called when the end of the sample is reached
	//
	void flush(sinsp_evt* evt,
	           uint64_t flush_time,
	           bool is_eof,
	           analyzer_emitter::flush_flags flshflags);

	//
	// Called by the engine after opening the event source and before
	// receiving the first event. Can be used to make adjustments based on
	// the user's changes to the configuration.
	//
	void on_capture_start();

	std::vector<cpustate2> m_cpu_states;

private:
	void update(THREAD_TYPE* tinfo, uint64_t ts, int16_t cpu, int64_t nexttid);

	sinsp_analyzer& m_analyzer;
	sinsp* m_inspector;
	uint32_t m_ncpus;
	uint64_t m_sample_length_ns;
};
