#include "app_check_emitter.h"
#include "analyzer_thread.h"

app_check_emitter::app_check_emitter(app_checks_proxy::metric_map_t& app_metrics,
				     const uint16_t app_metrics_limit,
				     const prometheus_conf& prom_conf,
				     std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& app_checks_by_container,
				     std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& prometheus_by_container,
				     const uint64_t prev_flush_time_ns)
	: m_app_metrics(app_metrics),
	  m_app_metrics_limit(app_metrics_limit),
	  m_app_metrics_remaining(app_metrics_limit),
	  m_prom_conf(prom_conf),
	  m_prom_metrics_remaining(m_prom_conf.max_metrics()),
	  m_app_checks_by_container(app_checks_by_container),
	  m_prometheus_by_container(prometheus_by_container),
	  m_prev_flush_time_ns(prev_flush_time_ns)
{
}

void app_check_emitter::emit_apps(sinsp_procinfo& procinfo,
				  sinsp_threadinfo& tinfo,
				  draiosproto::process& proc)
{
	// Send data for each app-check for the processes in procinfo
	unsigned sent_app_checks_metrics = 0;
	unsigned filtered_app_checks_metrics = 0;
	unsigned total_app_checks_metrics = 0;
	unsigned sent_prometheus_metrics = 0;
	unsigned filtered_prometheus_metrics = 0;
	unsigned total_prometheus_metrics = 0;
	// Map of app_check data by app-check name and how long the
	// metrics have been expired to ensure we serve the most recent
	// metrics available
	map<string, map<int, const app_check_data *>> app_data_to_send;
	for(auto pid: procinfo.m_program_pids)
	{
		auto datamap_it = m_app_metrics.find(pid);
		if(datamap_it == m_app_metrics.end())
			continue;
		for(const auto& app_data : datamap_it->second)
		{
			int age = (m_prev_flush_time_ns/ONE_SECOND_IN_NS) -
				app_data.second.expiration_ts();
			app_data_to_send[app_data.first][age] = &(app_data.second);
		}
	}

	for(auto app_age_map : app_data_to_send)
	{
		bool sent = false;
		for(auto app_data : app_age_map.second)
		{
			if(sent)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG,
						"Skipping duplicate app metrics for %d(%d),%s:exp in %d",
						tinfo.m_pid, app_data.second->pid(),
						app_age_map.first.c_str(), -app_data.first);
				continue;
			}
			g_logger.format(sinsp_logger::SEV_DEBUG,
					"Found app metrics for %d(%d),%s, exp in %d", tinfo.m_pid, app_data.second->pid(),
					app_age_map.first.c_str(), -app_data.first);
			sent = true;

#ifndef CYGWING_AGENT
			if(app_data.second->type() == app_check_data::check_type::PROMETHEUS)
			{
				static bool logged_metric = false;
				unsigned metric_count;
				metric_count = app_data.second->to_protobuf(proc.mutable_protos()->mutable_prometheus(),
									    m_prom_metrics_remaining,
									    m_prom_conf.max_metrics());
				sent_prometheus_metrics += metric_count;
				if(!logged_metric && metric_count)
				{
					const auto metrics = app_data.second->metrics();
					// app_check_data::to_protobuf() returns the total number of metrics
					// and service checks, so it's possible for metrics() to be empty
					// even when metric_count is not zero.
					// We May want to add some logging of service checks in case we don't have metrics
					if(!metrics.empty())
					{
						g_logger.log("Starting export of Prometheus metrics",
							     sinsp_logger::SEV_INFO);
						const string &metricname = metrics[0].name();
						g_logger.format(sinsp_logger::SEV_DEBUG,
								"First prometheus metrics since agent start: pid %d: %d metrics including: %s",
								app_data.second->pid(), metric_count, metricname.c_str());
						logged_metric = true;
					}
				}
				filtered_prometheus_metrics += app_data.second->num_metrics();
				total_prometheus_metrics += app_data.second->total_metrics();
			}
			else
#endif
			{
				sent_app_checks_metrics += app_data.second->to_protobuf(proc.mutable_protos()->mutable_app(),
											m_app_metrics_remaining,
											m_app_metrics_limit);
				filtered_app_checks_metrics += app_data.second->num_metrics();
				total_app_checks_metrics += app_data.second->total_metrics();
			}
		}
	}
	proc.mutable_resource_counters()->set_app_checks_sent(sent_app_checks_metrics);
	proc.mutable_resource_counters()->set_app_checks_total(total_app_checks_metrics);
	proc.mutable_resource_counters()->set_prometheus_sent(sent_prometheus_metrics);
	proc.mutable_resource_counters()->set_prometheus_total(total_prometheus_metrics);
	if(!tinfo.m_container_id.empty())
	{
		std::get<0>(m_app_checks_by_container[tinfo.m_container_id]) += sent_app_checks_metrics;
		std::get<1>(m_app_checks_by_container[tinfo.m_container_id]) += total_app_checks_metrics;
		std::get<0>(m_prometheus_by_container[tinfo.m_container_id]) += sent_prometheus_metrics;
		std::get<1>(m_prometheus_by_container[tinfo.m_container_id]) += total_prometheus_metrics;
	}
	std::get<0>(m_app_checks_by_container[""]) += sent_app_checks_metrics;
	std::get<1>(m_app_checks_by_container[""]) += total_app_checks_metrics;
	std::get<0>(m_prometheus_by_container[""]) += sent_prometheus_metrics;
	std::get<1>(m_prometheus_by_container[""]) += total_prometheus_metrics;
	m_num_app_check_metrics_sent += sent_app_checks_metrics;
	m_num_app_check_metrics_filtered += filtered_app_checks_metrics;
	m_num_app_check_metrics_total += total_app_checks_metrics;

	m_num_prometheus_metrics_sent += sent_prometheus_metrics;
	m_num_prometheus_metrics_filtered += filtered_prometheus_metrics;
	m_num_prometheus_metrics_total += total_prometheus_metrics;
}

void app_check_emitter::log_result()
{
	if(m_app_metrics_remaining == 0)
        {
                g_logger.format(sinsp_logger::SEV_WARNING,
				"App checks metrics limit (%u) reached, %u sent of %u filtered, %u total",
				m_app_metrics_limit,
				m_num_app_check_metrics_sent,
				m_num_app_check_metrics_filtered,
				m_num_app_check_metrics_total);
        } else {
                g_logger.format(sinsp_logger::SEV_DEBUG,
				"Sent %u Appcheck metrics of %u filtered, %u total",
				m_num_app_check_metrics_sent,
				m_num_app_check_metrics_filtered,
				m_num_app_check_metrics_total);
        }

#ifndef CYGWING_AGENT
        if(m_prom_metrics_remaining == 0)
        {
                g_logger.format(sinsp_logger::SEV_WARNING,
				"Prometheus metrics limit (%u) reached, %u sent of %u filtered, %u total",
				m_prom_conf.max_metrics(),
				m_num_prometheus_metrics_sent,
				m_num_prometheus_metrics_filtered,
				m_num_prometheus_metrics_total);
        } else {
                g_logger.format(sinsp_logger::SEV_DEBUG,
				"Sent %u Prometheus metrics of %u filtered, %u total",
				m_num_prometheus_metrics_sent,
				m_num_prometheus_metrics_filtered,
				m_num_prometheus_metrics_total);
        }
#endif

}
	
