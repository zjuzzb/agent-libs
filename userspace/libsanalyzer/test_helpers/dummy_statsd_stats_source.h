/**
 * @file
 *
 * Interface to dummy_statsd_stats_source.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "metric_limits.h"
#include "statsite_proxy.h"
#include <string>
#include <vector>

namespace test_helpers
{

/**
 * A dummy implementation of statsd_stats_source.  Clients can prepopulate
 * what read_metrics() returns.  This enables us to test APIs that call
 * read_metrics() without having to actually read any metrics.
 */
class dummy_statsd_stats_source : public statsd_stats_source
{
public:
	using taglist = std::vector<std::string>;

	/**
	 * Returns the metrics that have been added since creation or since
	 * the last call to read_metrics.  Clears the metrics associated with
	 * this object.
	 */
	statsd_stats_source::container_statsd_map read_metrics(
			metric_limits::cref_sptr_t ml = nullptr) override;


	/**
	 * Add a counter-type metric with the given properties.
	 */
	void add_counter(const std::string& name,
	                 double value,
	                 uint64_t ts,
	                 const std::string& container_id = "",
	                 const taglist& tags = taglist());

	/**
	 * Add a set-type metric with the given properties.
	 */
	void add_set(const std::string& name,
	             double value,
	             uint64_t ts,
	             const std::string& container_id = "",
	             const taglist& tags = taglist());

	/**
	 * Add a gauge-type metric with the given properties.
	 */
	void add_gauge(const std::string& name,
	               double value,
	               uint64_t ts,
	               const std::string& container_id = "",
	               const taglist& tags = taglist());

	/**
	 * Add a histogram-type metric with the given properties.
	 */
	void add_histogram(const std::string& name,
	                   double value,
	                   uint64_t ts,
	                   const std::string& container_id = "",
	                   const taglist& tags = taglist());

	/**
	 * Encodes a metric name based on the given name and container id.
	 * If the container_id is empty, then the returned value is just the
	 * name.  If not, then the returned value is the
	 * name + $ + container_id.
	 */
	static std::string encode_name(const std::string& name,
	                               const std::string& container_id = "");

	/**
	 * Encodes the given list of tags.  If there are no tags, then this
	 * returns the empty string.  Otherwise, it returns
	 * "#tag_name:tag_value[,tag_name:tag_value,...]"
	 */
	static std::string encode_tags(const taglist& tags);

private:
	/**
	 * Adds the metric encoded in the given parameter.
	 */
	void add_metric(const std::string& metric);

	/**
	 * The metrics that have been added (and will be returned by
	 * read_metrics())
	 */
	statsd_stats_source::container_statsd_map m_stats;
};

} // namespace test_helpers
