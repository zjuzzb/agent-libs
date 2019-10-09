#pragma once

#include <atomic>
#include <memory>
#include <stdint.h>

#include "draios.pb.h"


/**
 * This is the message the analyzer sends once flush() is done. It contains
 * all the data from the flush operation for further processing by the
 * emit pipeline.
 */
struct flush_data_message
{
	flush_data_message(uint64_t evt_num,
	                   uint64_t ts,
	                   uint32_t sampling_ratio,
	                   double prev_flush_cpu_pct,
	                   uint64_t prev_flushes_duration_ns,
	                   std::atomic<bool>& metrics_sent,
	                   double my_cpuload,
	                   int64_t n_proc_lookups,
	                   int64_t n_main_thread_lookups,
	                   const draiosproto::metrics& metrics):
	    m_evt_num(evt_num),
	    m_ts(ts),
	    m_sampling_ratio(sampling_ratio),
	    m_prev_flush_cpu_pct(prev_flush_cpu_pct),
	    m_prev_flushes_duration_ns(prev_flushes_duration_ns),
	    m_metrics_sent(metrics_sent),
	    m_my_cpuload(my_cpuload),
	    m_n_proc_lookups(n_proc_lookups),
	    m_n_main_thread_lookups(n_main_thread_lookups),
	    m_metrics(std::make_shared<draiosproto::metrics>(metrics))
	{
	}


	const uint64_t m_evt_num;
	const uint64_t m_ts;
	const uint32_t m_sampling_ratio;
	const double m_prev_flush_cpu_pct;
	const uint64_t m_prev_flushes_duration_ns;
	std::atomic<bool>& m_metrics_sent;
	const double m_my_cpuload;
	const int64_t m_n_proc_lookups;
	const int64_t m_n_main_thread_lookups;
	std::shared_ptr<draiosproto::metrics> m_metrics;
};
