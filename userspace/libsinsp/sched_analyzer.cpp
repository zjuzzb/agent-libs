#include "sinsp.h"
#include "sinsp_int.h"
#include "connectinfo.h"
#include "analyzer.h"
#include "sched_analyzer.h"

///////////////////////////////////////////////////////////////////////////////
// cpustate implementation
///////////////////////////////////////////////////////////////////////////////
cpustate::cpustate()
{
	init();
}

void cpustate::init()
{
	m_last_switch_time = 0;
	m_last_switch_tid = 0;
	m_last_time_segment = 0;
	m_last_interval_threads.clear();
}

vector<pair<int64_t, uint64_t>>::iterator cpustate::find_thread(int64_t tid)
{
	vector<pair<int64_t, uint64_t>>::iterator it;

	for(it = m_last_interval_threads.begin(); it != m_last_interval_threads.end(); ++it)
	{
		if(it->first == tid)
		{
			return it;
		}
	}

	return it;
}

void cpustate::add_to_last_interval(int64_t tid, uint64_t delta)
{
	vector<pair<int64_t, uint64_t>>::iterator it = find_thread(tid);

	if(it == m_last_interval_threads.end())
	{
		m_last_interval_threads.push_back(pair<int64_t, uint64_t>(tid, delta));
	}
	else
	{
		it->second += delta;
	}
}

void cpustate::complete_interval()
{
	vector<pair<int64_t, uint64_t>>::iterator it;
	uint64_t max = 0;
	int64_t max_pid = -1;
#ifdef _DEBUG
	uint64_t tot = 0;
#endif

	for(it = m_last_interval_threads.begin(); it != m_last_interval_threads.end(); ++it)
	{
		if(it->second > max)
		{
			max = it->second;
			max_pid = it->first;
		}

#ifdef _DEBUG
		tot += it->second;
#endif
	}

	if(max_pid != -1)
	{
		m_time_segments[m_last_time_segment] = max_pid;
	}

	ASSERT(tot = CONCURRENCY_OBSERVATION_INTERVAL_NS);
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_sched_analyzer implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_sched_analyzer::sinsp_sched_analyzer(sinsp* inspector, uint32_t ncpus)
{
	ASSERT(inspector != NULL);
	m_ncpus = ncpus;
	m_inspector = inspector;
	m_cpu_states = vector<cpustate>(ncpus);
}

void sinsp_sched_analyzer::on_capture_start()
{
	uint32_t j;
	m_sample_length_ns = (size_t)m_inspector->m_configuration.get_analyzer_sample_length_ns();

	for(j = 0; j < m_ncpus; j++)
	{
		m_cpu_states[j].m_time_segments = 
			vector<int64_t>((size_t)m_sample_length_ns / CONCURRENCY_OBSERVATION_INTERVAL_NS, 0);
	}
}

void sinsp_sched_analyzer::update(uint64_t ts, int16_t cpu, int64_t nexttid)
{
	uint32_t j;
	cpustate& state = m_cpu_states[cpu];
	uint64_t time_in_sample = ts % m_sample_length_ns;
	uint32_t cursegment = (uint32_t)time_in_sample / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	int64_t oldtid = state.m_last_switch_tid;
	int64_t delta;

	//
	// This can happen because we don't trigger sample switch with scheduler events.
	// As a consequence, we can get a context switch event *before* its sample starts.
	// We skip it here and we take care of it in flush().
	//
	if(cursegment < state.m_last_time_segment)
	{
		state.m_last_switch_tid = nexttid;
		return;
	}

	//
	// If this is the first sample, just init the values
	//
	if(state.m_last_switch_time == 0)
	{
		state.m_last_switch_time = ts;
		state.m_last_switch_tid = nexttid;
		state.m_last_time_segment = cursegment;
		return;
	}

	if(cursegment > state.m_last_time_segment)
	{
		//
		// We went into a new segment.
		// First of all, complete the one where we were previously
		//
		uint64_t old_segment_end = state.m_last_switch_time / CONCURRENCY_OBSERVATION_INTERVAL_NS * CONCURRENCY_OBSERVATION_INTERVAL_NS + CONCURRENCY_OBSERVATION_INTERVAL_NS;
		delta = (int64_t)(old_segment_end - state.m_last_switch_time);

		state.add_to_last_interval(state.m_last_switch_tid, delta);

		state.complete_interval();

		//
		// Now fill the intermediate intervals with the current pid
		//
		for(j = state.m_last_time_segment + 1; j < cursegment; j++)
		{
			state.m_time_segments[j] = oldtid;
		}

		//
		// Now reset the interval stats
		//
		state.m_last_interval_threads.clear();
		uint64_t observation_start = ts / CONCURRENCY_OBSERVATION_INTERVAL_NS * CONCURRENCY_OBSERVATION_INTERVAL_NS;
		delta = (int64_t)(ts - observation_start);
	}
	else
	{
		delta = (int64_t)(ts - state.m_last_switch_time);
	}

	//
	// Update the current sample
	//
	state.add_to_last_interval(state.m_last_switch_tid, delta);

	state.m_last_switch_time = ts;
	state.m_last_switch_tid = nexttid;
	state.m_last_time_segment = cursegment;
}

void sinsp_sched_analyzer::process_event(sinsp_evt* evt)
{
	int16_t cpu = evt->get_cpuid();
	uint64_t ts = evt->get_ts();
	ASSERT(cpu < (int16_t)m_cpu_states.size());

	//
	// Extract the tid
	//
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t nexttid = *(int64_t *)parinfo->m_val;

	update(ts, cpu, nexttid);
}

void sinsp_sched_analyzer::flush(sinsp_evt* evt, uint64_t flush_time, bool is_eof)
{
	uint32_t j;

	for(j = 0; j < m_ncpus; j++)
	{
		cpustate& state = m_cpu_states[j];

		if(state.m_last_switch_time == 0 || state.m_last_time_segment == 0)
		{
			//
			// No context switch for this processor yet
			//
			continue;
		}

		//
		// Complete the state for this CPU
		//
		update(flush_time - 1, j, state.m_last_switch_tid);
		state.complete_interval();

		//
		// Reset the state so we're ready for the next sample
		//
		state.m_last_time_segment = 0;
		state.m_last_interval_threads.clear();
		state.m_last_switch_time = flush_time;

#if 1
		uint32_t nused = 0;

		for(uint32_t k = 0; k < state.m_time_segments.size(); k++)
		{
			if(state.m_time_segments[k] != 0)
			{
				nused++;
			}
		}

		g_logger.format(sinsp_logger::SEV_DEBUG, 
			"CPU %" PRIu32 " estimated usage:%.2f",
			j,
			(float)nused * 100 / state.m_time_segments.size());
#endif
	}
}

///////////////////////////////////////////////////////////////////////////////
// cpustate2 implementation
///////////////////////////////////////////////////////////////////////////////
cpustate2::cpustate2()
{
	init();
}

void cpustate2::init()
{
	m_last_switch_time = 0;
	m_last_switch_tid = 0;
	m_idle_ns = 0;
	m_other_ns = 0;
	m_unknown_ns = 0;
	m_server_processes_ns = 0;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_sched_analyzer2 implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_sched_analyzer2::sinsp_sched_analyzer2(sinsp* inspector, uint32_t ncpus)
{
	ASSERT(inspector != NULL);
	m_ncpus = ncpus;
	m_inspector = inspector;
	m_cpu_states = vector<cpustate2>(ncpus);
	m_last_effective_sample_start = 0;
	m_sample_effective_length_ns = 0;
}

void sinsp_sched_analyzer2::on_capture_start()
{
}

void sinsp_sched_analyzer2::update(sinsp_threadinfo* tinfo, uint64_t ts, int16_t cpu, int64_t nexttid)
{
	cpustate2& state = m_cpu_states[cpu];
	int64_t delta;

	//
	// If this is the first sample, just init the values
	//
	if(state.m_last_switch_time == 0)
	{
		state.m_last_switch_time = ts;
		state.m_last_switch_tid = nexttid;
		m_last_effective_sample_start = ts;
		return;
	}

	//
	// Calculate the delta
	//
	delta = (int64_t)(ts - state.m_last_switch_time);
	ASSERT(delta >= 0);
	ASSERT(delta < (int64_t)m_inspector->m_configuration.get_analyzer_sample_length_ns());

	//
	// Attribute the delta to the proper thread
	//
	if(tinfo == NULL)
	{
		if(state.m_last_switch_tid == 0)
		{
			state.m_idle_ns += delta;
		}
		else
		{
			state.m_unknown_ns += delta;
		}
	}
	else
	{
		if(tinfo->m_cpu_time_ns.size() != m_ncpus)
		{
			ASSERT(tinfo->m_cpu_time_ns.size() == 0);
			tinfo->m_cpu_time_ns.resize(m_ncpus);
		}

		tinfo->m_cpu_time_ns[cpu] += delta;

		if(tinfo->m_th_analysis_flags & sinsp_threadinfo::AF_IS_SERVER)
		{
			state.m_server_processes_ns += delta;
		}
		else
		{
			state.m_other_ns += delta;
		}
	}

	//
	// Update the current sample
	//
	state.m_last_switch_time = ts;
	state.m_last_switch_tid = nexttid;
}

void sinsp_sched_analyzer2::process_event(sinsp_evt* evt)
{
	int16_t cpu = evt->get_cpuid();
	uint64_t ts = evt->get_ts();
	ASSERT(cpu < (int16_t)m_cpu_states.size());

	//
	// Extract the tid
	//
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t nexttid = *(int64_t *)parinfo->m_val;

	update(evt->get_thread_info(), ts, cpu, nexttid);
}

void sinsp_sched_analyzer2::flush(sinsp_evt* evt, uint64_t flush_time, bool is_eof)
{
	uint32_t j;

	for(j = 0; j < m_ncpus; j++)
	{
		cpustate2& state = m_cpu_states[j];

		if(state.m_last_switch_time == 0)
		{
			//
			// No context switch for this processor yet
			//
			continue;
		}

		//
		// Complete the state for this CPU
		//
		sinsp_threadinfo* tinfo = m_inspector->get_thread(state.m_last_switch_tid, false);
		uint64_t utime = MAX(flush_time - 1, state.m_last_switch_time);
		update(tinfo, utime, j, state.m_last_switch_tid);

		//
		// Reset the state so we're ready for the next sample
		//
		state.m_last_switch_time = flush_time;
		state.m_lastsample_idle_ns = state.m_idle_ns;
		state.m_lastsample_other_ns = state.m_other_ns;
		state.m_lastsample_unknown_ns = state.m_unknown_ns;
		state.m_lastsample_server_processes_ns = state.m_server_processes_ns;
		state.m_idle_ns = 0;
		state.m_other_ns = 0;
		state.m_unknown_ns = 0;
		state.m_server_processes_ns = 0;
		m_sample_effective_length_ns = utime - m_last_effective_sample_start;
		m_last_effective_sample_start = utime;

#if 1
		g_logger.format(sinsp_logger::SEV_DEBUG, 
			"***CPU %" PRIu32 " server:%" PRIu64 " other:%" PRIu64 " unknown:%" PRIu64 " idle:%" PRIu64 " idle1:%" PRIu32,
			j,
			state.m_lastsample_server_processes_ns,
			state.m_lastsample_other_ns,
			state.m_lastsample_unknown_ns,
			state.m_lastsample_idle_ns,
			(m_inspector->m_analyzer->m_cpu_idles.size() != 0)?m_inspector->m_analyzer->m_cpu_idles[j] : 0);
#endif
	}
}
