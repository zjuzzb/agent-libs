/**
 * @file
 *
 * Interface to statsite_statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "statsd_emitter.h"
#include "statsite_proxy.h"
#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace libsanalyzer {

/**
 * A concrete statsd_emitter that pulls statsd metrics from statsite.
 */
class statsite_statsd_emitter : public statsd_emitter
{
public:
	/**
	 * Initialize this new statsite_statsd_emitter.
	 *
	 * @param[in] stats_source The source of the stats
	 *                         (e.g., statsite_proxy).
	 * @param[in] limits       Configured metric limits, if any.
	 */
	statsite_statsd_emitter(const statsd_stats_source::ptr& stats_source,
	                        const metric_limits::sptr_t& limits);

	/**
	 * Fetch metrics from the associated metric source.
	 *
	 * @param[in] prev_flush_time_ns A timestamp use to filter out "old"
	 *                               metrics (if there are any).
	 */
	void fetch_metrics(uint64_t prev_flush_time_ns) override;

	/**
	 * Emit any host metrics in collected in the previous call to
	 * fetch_metrics.
	 */
	void emit(::draiosproto::host* host,
	          ::draiosproto::statsd_info* metrics) override;

	/**
	 * Emit any container metrics in collected in the previous call to
	 * fetch_metrics.
	 */
	unsigned emit(const std::string& container_id,
	              const std::string& container_name,
	              ::draiosproto::container* container,
	              unsigned limit) override;

private:
	statsd_stats_source::container_statsd_map m_statsd_metrics;
	statsd_stats_source::ptr m_statsd_stats_source;
	metric_limits::sptr_t m_metric_limits;
};

} // namespace libsanalyzer
