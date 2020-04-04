#define __STDC_FORMAT_MACROS

#include "analyzer.h"
#include "analyzer_int.h"
#include "analyzer_thread.h"
#include "common_logger.h"
#include "connectinfo.h"
#include "sched_analyzer.h"
#include "sinsp.h"
#include "sinsp_int.h"

#include <inttypes.h>

COMMON_LOGGER();

///////////////////////////////////////////////////////////////////////////////
// cpustate2 implementation
///////////////////////////////////////////////////////////////////////////////
cpustate2::cpustate2()
{
	m_lastsample_idle_ns = 0;
	m_lastsample_other_ns = 0;
	m_lastsample_unknown_ns = 0;
	m_lastsample_server_processes_ns = 0;

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
	m_last_effective_sample_start = 0;
	m_sample_effective_length_ns = 0;
	m_last_flush_time = 0;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_sched_analyzer2 implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_sched_analyzer2::sinsp_sched_analyzer2(sinsp_analyzer& analyzer,
                                             sinsp* inspector,
                                             uint32_t ncpus)
    : m_analyzer(analyzer),
      m_inspector(inspector),
      m_ncpus(ncpus)
{
	ASSERT(inspector != NULL);
	m_cpu_states = std::vector<cpustate2>(ncpus);
}

void sinsp_sched_analyzer2::on_capture_start()
{
	m_sample_length_ns = (size_t)m_analyzer.get_sample_duration();
}

void sinsp_sched_analyzer2::update(thread_analyzer_info* tinfo, uint64_t ts, int16_t cpu, int64_t nexttid)
{
	cpustate2& state = m_cpu_states[cpu];
	int64_t delta;

	//
	// If this is the first sample, just init the values
	//
	if (state.m_last_switch_time == 0)
	{
		state.m_last_switch_time = ts;
		state.m_last_switch_tid = nexttid;
		state.m_last_effective_sample_start = ts;
		return;
	}

	//
	// Calculate the delta
	//
	delta = (int64_t)(ts - state.m_last_switch_time);

	//
	// Account for cross-sample gaps
	//
	if (delta > (int64_t)m_sample_length_ns)
	{
		uint64_t sample_start = ts / m_sample_length_ns * m_sample_length_ns;

		if (state.m_last_switch_time < sample_start)
		{
			state.m_last_switch_time = sample_start;
			delta = (int64_t)(ts - state.m_last_switch_time);
		}
	}

	if (delta <= 0)
	{
		return;
	}

	ASSERT(delta < (int64_t)m_analyzer.get_sample_duration());

	//
	// Attribute the delta to the proper thread
	//
	if (tinfo == NULL)
	{
		if (state.m_last_switch_tid == 0)
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
		if (tinfo->m_cpu_time_ns.size() != m_ncpus)
		{
			ASSERT(tinfo->m_cpu_time_ns.size() == 0);
			tinfo->m_cpu_time_ns.resize(m_ncpus);
		}

		tinfo->m_cpu_time_ns[cpu] += delta;

		//
		// XXX
		// including AF_IS_UNIX_SERVER could catch a lot of noise from stuff like dbus-daemon.
		// Don't really know how to address it.
		//
		if (tinfo->m_th_analysis_flags &
		    (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER |
		     thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
		     thread_analyzer_info::AF_IS_UNIX_SERVER))
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
	sinsp_evt_param* parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t nexttid = *(int64_t*)parinfo->m_val;

	update(thread_analyzer_info::get_thread_from_event(evt), ts, cpu, nexttid);
}

void sinsp_sched_analyzer2::flush(sinsp_evt* evt,
                                  uint64_t flush_time,
                                  bool is_eof,
                                  analyzer_emitter::flush_flags flshflags)
{
	uint32_t j;

	m_sample_length_ns = (size_t)m_analyzer.get_sample_duration();

	for (j = 0; j < m_ncpus; j++)
	{
		cpustate2& state = m_cpu_states[j];

		if (state.m_last_switch_time == 0)
		{
			//
			// No context switch for this processor yet
			//
			continue;
		}

		//
		// Complete the state for this CPU
		//
		thread_analyzer_info* tinfo = m_analyzer.get_mutable_thread_by_pid(state.m_last_switch_tid, false, true);
		uint64_t utime = MAX(flush_time - 1, state.m_last_switch_time);
		update(tinfo, utime, j, state.m_last_switch_tid);

		//
		// Reset the state so we're ready for the next sample
		//
		state.m_last_switch_time = flush_time;
		state.m_last_flush_time = flush_time;
		state.m_lastsample_idle_ns = state.m_idle_ns;
		state.m_lastsample_other_ns = state.m_other_ns;
		state.m_lastsample_unknown_ns = state.m_unknown_ns;
		state.m_lastsample_server_processes_ns = state.m_server_processes_ns;
		state.m_idle_ns = 0;
		state.m_other_ns = 0;
		state.m_unknown_ns = 0;
		state.m_server_processes_ns = 0;
		state.m_sample_effective_length_ns = utime - state.m_last_effective_sample_start;
		state.m_last_effective_sample_start = utime;

		if (flshflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
		{
			                LOG_DEBUG("CPU %" PRIu32 " srv:%" PRIu64 " o:%" PRIu64 " u:%" PRIu64 " i:%" PRIu64
			                "(c:%lf i:%lf s:%lf)",
			                j,
			                state.m_lastsample_server_processes_ns,
			                state.m_lastsample_other_ns,
			                state.m_lastsample_unknown_ns,
			                state.m_lastsample_idle_ns,
			                m_analyzer.has_cpu_load_data() ? m_analyzer.get_cpu_load_data(j) : 0,
			                m_analyzer.has_cpu_idle_data() ? m_analyzer.get_cpu_idle_data(j) : 0,
			                m_analyzer.has_cpu_steal_data() ? m_analyzer.get_cpu_steal_data(j) : 0);
		}
	}
}
