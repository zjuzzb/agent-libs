/**
 * @file
 *
 * Implementation of dummy_statsd_stats_source.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dummy_statsd_stats_source.h"

namespace test_helpers
{

statsd_stats_source::container_statsd_map dummy_statsd_stats_source::read_metrics(
		metric_limits::cref_sptr_t ml)
{
	const statsd_stats_source::container_statsd_map ret = m_stats;

	m_stats = statsd_stats_source::container_statsd_map();

	return ret;
}

void dummy_statsd_stats_source::add_metric(const std::string& metric)
{
	statsd_metric m;

	if(!m.parse_line(metric))
	{
		throw std::runtime_error("Failed to parse metric: " + metric);
	}

	const std::string id = m.container_id();

	std::get<0>(m_stats[id]).push_back(m);
	++std::get<1>(m_stats[id]);
}

void dummy_statsd_stats_source::add_counter(const std::string& name,
                                            const double value,
		                            const uint64_t ts,
		                            const std::string& container_id,
	                                    const taglist& tags)

{
	const std::string metric = "counts." +
	                           encode_name(name, container_id) +
	                           encode_tags(tags) + "|" +
	                           std::to_string(value) + "|" +
	                           std::to_string(ts);

	add_metric(metric);
}

void dummy_statsd_stats_source::add_set(const std::string& name,
	                                const double value,
	                                const uint64_t ts,
	                                const std::string& container_id,
	                                const taglist& tags)
{
	const std::string metric = "sets." +
	                           encode_name(name, container_id) +
	                           encode_tags(tags) + "|" +
	                           std::to_string(value) + "|" +
	                           std::to_string(ts);

	add_metric(metric);
}

void dummy_statsd_stats_source::add_gauge(const std::string& name,
                                          const double value,
	                                  const uint64_t ts,
	                                  const std::string& container_id,
	                                  const taglist& tags)
{
	const std::string metric = "gauges." +
	                           encode_name(name, container_id) +
	                           encode_tags(tags) + "|" +
	                           std::to_string(value) + "|" +
	                           std::to_string(ts);

	add_metric(metric);
}

void dummy_statsd_stats_source::add_histogram(const std::string& name,
                                              const double value,
		                              const uint64_t ts,
		                              const std::string& container_id,
	                                      const taglist& tags)
{
	using subtype_value_map = std::map<std::string, double>;

	static double seq = 0;

	const subtype_value_map values = {
		{ ".sum",         value },
		{ ".sum_sq",      ++seq },
		{ ".mean",        value },
		{ ".lower",       value },
		{ ".upper",       value },
		{ ".count",       1.0   },
		{ ".stdev",       0.0   },
		{ ".median",      value },
		{ ".p50",         value },
		{ ".p95",         value },
		{ ".p99",         value },
		{ ".rate",        value },
		{ ".sample_rate", value },
	};

	statsd_metric m;

	for(const auto& i : values)
	{
		const std::string metric = "timers." +
		                           encode_name(name, container_id) +
	                                   encode_tags(tags) +
		                           i.first + "|" +
		                           std::to_string(i.second) + "|" +
		                           std::to_string(ts);

		if(!m.parse_line(metric))
		{
			throw std::runtime_error("Failed to parse metric: " + metric);
		}
	}

	std::get<0>(m_stats[container_id]).push_back(m);
	++std::get<1>(m_stats[container_id]);
}

std::string dummy_statsd_stats_source::encode_name(
		const std::string& name,
		const std::string& container_id)
{
	if(container_id.empty())
	{
		return name;
	}
	else
	{
		return container_id + "$" + name;
	}
}

std::string dummy_statsd_stats_source::encode_tags(const taglist& tags)
{
	std::string tagstr;

	auto i = tags.begin();

	if(i != tags.end())
	{
		tagstr = "#" + *i;

		for(++i; i != tags.end(); ++i)
		{
			tagstr += "," + *i;
		}
	}

	return tagstr;
}

} // namespace test_helpers

