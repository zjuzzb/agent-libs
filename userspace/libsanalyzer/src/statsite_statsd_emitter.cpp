/**
 * @file
 *
 * Implementation of statsite_statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsite_statsd_emitter.h"
#include "draios.pb.h"
#include "common_logger.h"
#include "utils.h"
#include <memory>
#include <string>
#include <vector>

namespace
{

unsigned emit_metrics(const std::vector<statsd_metric>& metric_list,
                      ::draiosproto::statsd_info* const statsd_info,
                      const unsigned limit,
                      const unsigned max_limit,
                      const std::string& context)
{
	unsigned num_metrics = 0;

	for(const auto& metric : metric_list)
	{
		if(num_metrics >= limit)
		{
			if(metric_limits::log_enabled())
			{
				SINSP_INFO("[statsd] metric over limit "
				           "(total, %u max): %s",
				           max_limit,
				           metric.name().c_str());
			}
			else
			{
				SINSP_WARNING("statsd metrics over limit, "
				              "giving up");
				break;
			}
		}
		else
		{
			auto statsd_proto = statsd_info->add_statsd_metrics();

			metric.to_protobuf(statsd_proto);
			++num_metrics;
		}
	}

	if(num_metrics > 0)
	{
		SINSP_INFO("Added %d statsd metrics for %s",
		           num_metrics,
		           context.c_str());
	}

	return num_metrics;
}

} // end namespace

namespace libsanalyzer
{

statsite_statsd_emitter::statsite_statsd_emitter(
		const statsd_stats_source::ptr& stats_source,
		const metric_limits::sptr_t& limits):
	m_statsd_metrics(),
	m_statsd_stats_source(stats_source),
	m_metric_limits(limits)
{ }

void statsite_statsd_emitter::fetch_metrics(const uint64_t prev_flush_time_ns)
{
	const uint64_t one_sec_ns = 1000000000LL;

	// Look for statsite sample m_prev_flush_time_ns (now) - 1s which should
	// be always ready
	const uint64_t look_for_ts = ((prev_flush_time_ns - one_sec_ns) /
	                             one_sec_ns);

	if(m_statsd_metrics.empty())
	{
		m_statsd_metrics = m_statsd_stats_source->read_metrics(m_metric_limits);
	}

	while(!m_statsd_metrics.empty())
	{
		auto metrics = std::get<0>(m_statsd_metrics.begin()->second);

		if(metrics.empty())
		{
			break;
		}

		if(metrics.at(0).timestamp() >= look_for_ts)
		{
			break;
		}

		m_statsd_metrics = m_statsd_stats_source->read_metrics(m_metric_limits);
	}
}

void statsite_statsd_emitter::emit(::draiosproto::host* const host,
                                   ::draiosproto::statsd_info* const metrics)
{
	const unsigned limit = statsd_emitter::get_limit();

	const std::string HOST_KEY = "";

	::google::protobuf::uint64 statsd_total = 0;
	::google::protobuf::uint64 statsd_sent = 0;

	if(m_statsd_metrics.find(HOST_KEY) != m_statsd_metrics.end())
	{
		statsd_total = std::get<1>(m_statsd_metrics.at(HOST_KEY));
		statsd_sent = emit_metrics(
				std::get<0>(m_statsd_metrics.at(HOST_KEY)),
				metrics,
				limit,
				limit,
				"host=" + sinsp_gethostname());
	}

	host->mutable_resource_counters()->set_statsd_total(statsd_total);
	host->mutable_resource_counters()->set_statsd_sent(statsd_sent);
}

unsigned statsite_statsd_emitter::emit(const std::string& container_id,
                                       const std::string& container_name,
                                       ::draiosproto::container* const container,
                                       const unsigned limit)
{
	const unsigned max_limit = statsd_emitter::get_limit();

	unsigned new_limit = limit;
	::google::protobuf::uint64 statsd_total = 0;
	::google::protobuf::uint64 statsd_sent = 0;

	if(m_statsd_metrics.find(container_id) != m_statsd_metrics.end())
	{
		statsd_total = std::get<1>(m_statsd_metrics.at(container_id));
		statsd_sent = emit_metrics(
				std::get<0>(m_statsd_metrics.at(container_id)),
				container->mutable_protos()->mutable_statsd(),
				limit,
				max_limit,
				"container=" + container_name +
				" (id=" + container_id + ")");
		new_limit = limit - statsd_sent;
	}

	container->mutable_resource_counters()->set_statsd_total(statsd_total);
	container->mutable_resource_counters()->set_statsd_sent(statsd_sent);

	return new_limit;
}

} // namespace libsanalyzer
