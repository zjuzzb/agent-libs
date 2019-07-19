/**
 * @file
 *
 * Interface to statsite_proxy.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "metric_limits.h"
#include "statsd_stats_destination.h"
#include "statsd_stats_source.h"
#include <vector>
#include <Poco/RegularExpression.h>

class statsite_proxy : public statsd_stats_source,
                       public statsd_stats_destination
{
public:
	typedef std::unordered_map<std::string, std::vector<statsd_metric>> metric_map_t;

	statsite_proxy(const std::pair<FILE*, FILE*>& pipes,
		       bool check_format);
	statsd_stats_source::container_statsd_map read_metrics(
			metric_limits::cref_sptr_t ml = nullptr) override;
	void send_metric(const char *buf, uint64_t len) override;
	void send_container_metric(const std::string& container_id,
	                           const char* data,
	                           uint64_t len) override;

private:
	bool validate_buffer(const char *buf, uint64_t len);

	// This regex SHOULD match strings in such a way that each line goes:
	// stuff : stuff | stuff \n
	// except for the last one, which may or may not have a newline. See
	// the definition for a full breakdown of the regex
	static const std::string stats_validator_regex;
	static Poco::RegularExpression m_statsd_regex;

	FILE* m_input_fd;
	FILE* m_output_fd;
	statsd_metric m_metric;
	bool m_check_format = false;
};
