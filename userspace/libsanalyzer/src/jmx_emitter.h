#pragma once
#include "draios.pb.h"
#include "sinsp.h"
#include <unordered_map>
#include "jmx_proxy.h"

/**
 * Does the work of emitting the jmx metrics of processes during the scope of a SINGLE flush.
 *
 * emit_jmx must be invoked on each process which is inteded to have its jmx metrics
 * flushed
 */
class jmx_emitter{
public:
	jmx_emitter(const std::unordered_map<int, java_process>& jmx_metrics,
		    const uint32_t jmx_sampling,
		    const uint32_t jmx_limit,
		    std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& jmx_metrics_by_container);

	/**
	 * emit the jmx metrics for a single thread/proc
	 */
	void emit_jmx(sinsp_procinfo& procinfo,
		      sinsp_threadinfo& tinfo,
		      draiosproto::process& proc);
private:
	const unordered_map<int, java_process>& m_jmx_metrics;
	const uint32_t m_jmx_sampling;
	uint32_t m_jmx_limit_remaining;
	const uint32_t m_jmx_limit;
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& m_jmx_metrics_by_container;
};
