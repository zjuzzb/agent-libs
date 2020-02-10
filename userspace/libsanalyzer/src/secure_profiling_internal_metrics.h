#pragma once

class secure_profiling_internal_metrics
{
public:
	virtual ~secure_profiling_internal_metrics() = default;
	/**
	* Update secure profiling internal metrics.
	*
	* @param[in] n_sent_protobufs the number of sent protobufs.
	* @param[in] flush_time_ms secure profiling flush time in milliseconds.
	*/
	virtual void set_secure_profiling_internal_metrics(int n_sent_protobufs,
							   uint64_t flush_time_ms) = 0;
};
