/**
 * @file
 *
 * Interface to statsd_stats_source.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "statsd_metric.h"
#include <memory>
#include <vector>

/**
 * Interface to an object from which clients can read statsd messages.
 */
class statsd_stats_source
{
public:
	using ptr = std::shared_ptr<statsd_stats_source>;

	/** List of metrics */
	using statsd_metric_list = std::vector<statsd_metric>;

	/** <List of metrics, count> */
	using statsd_list_tuple = std::tuple<statsd_metric_list, unsigned>;

	/** container_id -> <List of metrics, count> */
	using container_statsd_map = std::unordered_map<std::string, statsd_list_tuple>;

	virtual ~statsd_stats_source() = default;

	/**
	 * Returns all available statsd metrics.
	 */
	virtual container_statsd_map read_metrics(metric_limits::cref_sptr_t ml = nullptr) = 0;
};
