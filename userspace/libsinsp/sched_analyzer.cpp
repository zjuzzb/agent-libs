#include "sinsp.h"
#include "sinsp_int.h"
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
		ASSERT(it->second > 0);

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
	m_cpu_states = vector<cpustate>(4);
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

void sinsp_sched_analyzer::update(uint64_t ts, int16_t cpu, int64_t newtid)
{
	uint32_t j;
	cpustate& state = m_cpu_states[cpu];
	uint64_t time_in_sample = ts % m_sample_length_ns;
	uint32_t cursegment = (uint32_t)time_in_sample / CONCURRENCY_OBSERVATION_INTERVAL_NS;
	int64_t prev_pid = state.m_last_switch_tid;
	int64_t delta;

	//
	// This can happen because we don't trigger sample switch with scheduler events.
	// As a consequence, we can get a context switch event *before* its sample starts.
	// We skip it here and we take care of it in flush().
	//
	if(cursegment < state.m_last_time_segment)
	{
		state.m_last_switch_tid = newtid;
		return;
	}

	//
	// If this is the first sample, just init the values
	//
	if(state.m_last_switch_time == 0)
	{
		state.m_last_switch_time = ts;
		state.m_last_switch_tid = newtid;
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
			state.m_time_segments[j] = prev_pid;
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
	ASSERT(delta > 0);

	state.add_to_last_interval(state.m_last_switch_tid, delta);

	state.m_last_switch_time = ts;
	state.m_last_switch_tid = newtid;
	state.m_last_time_segment = cursegment;
}

void sinsp_sched_analyzer::process_event(sinsp_evt* evt)
{
	int16_t cpu = evt->get_cpuid();
	uint64_t ts = evt->get_ts();
	ASSERT(cpu < (int16_t)m_cpu_states.size());
	// Validate the return value
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t newtid = *(int64_t *)parinfo->m_val;

	ASSERT(m_cpu_states[cpu].m_last_switch_tid == 0 || m_cpu_states[cpu].m_last_switch_tid == evt->get_tid());

	update(ts, cpu, newtid);
}

void sinsp_sched_analyzer::flush(sinsp_evt* evt, uint64_t flush_time, bool is_eof)
{
	uint32_t j;

	for(j = 0; j < m_ncpus; j++)
	{
		cpustate& state = m_cpu_states[j];

		//
		// Complete the state for this CPU
		//
		ASSERT(flush_time > state.m_last_switch_time);
		ASSERT(flush_time - state.m_last_switch_time <= m_inspector->m_configuration.get_analyzer_sample_length_ns());

		update(flush_time - 1, j, state.m_last_switch_tid);
		state.complete_interval();

		//
		// Reset the state so we're ready for the next sample
		//
		state.m_last_time_segment = 0;
		state.m_last_interval_threads.clear();
		state.m_last_switch_time = flush_time;

#ifdef _DEBUG
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
