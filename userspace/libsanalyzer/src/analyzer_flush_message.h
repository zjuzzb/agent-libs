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
	/**
     * Sentinel event number that indicates that a serialization operation
     * was not triggered by an event.
     */
    const static uint64_t NO_EVENT_NUMBER;

	flush_data_message(uint64_t ts,
	                   std::atomic<bool>* metrics_sent, // this is only used to set
					   									// to true the first time we send
														// data.
	                   const draiosproto::metrics& metrics,
					   // following metrics only used by metrics_file_emitter
					   // which probably shouldn't be in this path anyway
					   uint64_t nevts,
					   uint64_t num_drop_events,
	                   double my_cpuload,
	                   uint32_t sampling_ratio,
					   uint64_t n_tids_suppressed) :
	    m_ts(ts),
	    m_metrics_sent(metrics_sent),
	    m_metrics(std::make_shared<draiosproto::metrics>(metrics)),
		m_nevts(nevts),
		m_num_drop_events(num_drop_events),
		m_my_cpuload(my_cpuload),
		m_sampling_ratio(sampling_ratio),
		m_n_tids_suppressed(n_tids_suppressed)
	{
	}


	uint64_t m_ts;
	std::atomic<bool>* m_metrics_sent;
	std::shared_ptr<draiosproto::metrics> m_metrics;
	uint64_t m_nevts;
	uint64_t m_num_drop_events;
	double m_my_cpuload;
	uint32_t m_sampling_ratio;
	uint64_t m_n_tids_suppressed;
	uint32_t m_flush_interval = 0;
};
