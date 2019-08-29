#pragma once

#include <stdint.h>
#include <memory>

namespace draiosproto
{
class metrics;
}

/**
 * virtual class that defines the API invoked when the uncompressed protobuf for a given sample
 * is fully populated. Courtesy default implementations are provided
 */
class uncompressed_sample_handler
{
public:
	/**
	 * call when the uncompressed protobuf is fully populated and ready to be
	 * compressed or otherwise processed
	 *
	 * @param[in] ts_ns timestamp of the sample, in ns
	 * @param[in] nevts number of events included in this sample
	 * @param[in] num_drop_events number of dropped events in this sample timespan
	 * @param[in] metrics the protobuf containing the uncompressed data for this sample
	 * @param[in] sampling_ratio the maximum sampling ratio during this sample
	 * @param[in] analyzer_cpu_pct the average CPU usage of the analyzer during this sample
	 * @param[in] flush_cpu_pct the average usage of the CPU during flush
	 * @param[in] analyzer_flush_duration_ns the average duration of analyzer flush during this sample
	 * @param[in] num_suppressed_threads
	 */
	virtual void handle_uncompressed_sample(uint64_t ts_ns,
						uint64_t nevts,
						uint64_t num_drop_events,
						std::shared_ptr<draiosproto::metrics>& metrics,
						uint32_t sampling_ratio,
						double analyzer_cpu_pct,
						double flush_cpu_pct,
						uint64_t analyzer_flush_duration_ns,
						uint64_t num_suppressed_threads) = 0;

	/**
	 * returns the timestamp of the last invokation of handle_uncompressed_sample
	 */
	virtual uint64_t get_last_loop_ns() const = 0;
};

class uncompressed_sample_handler_dummy : public uncompressed_sample_handler
{
public:
	virtual void handle_uncompressed_sample(uint64_t ts_ns,
						uint64_t nevts,
						uint64_t num_drop_events,
						std::shared_ptr<draiosproto::metrics>& metrics,
						uint32_t sampling_ratio,
						double analyzer_cpu_pct,
						double flush_cpu_pct,
						uint64_t analyzer_flush_duration_ns,
						uint64_t num_suppressed_threads)
	{
	}

	virtual uint64_t get_last_loop_ns() const
	{
		return 0;
	}
};
