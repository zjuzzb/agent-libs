#include "app_check_emitter.h"
#include "analyzer_thread.h"
#include "configuration_manager.h"
#include "promscrape.h"
#include "prom_helper.h"
#include "common_logger.h"

COMMON_LOGGER();

app_check_emitter::app_check_emitter(const app_checks_proxy_interface::metric_map_t& app_metrics,
				     const unsigned int app_metrics_limit,
				     const prometheus_conf& prom_conf,
				     std::shared_ptr<promscrape> prom_scrape,
				     std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& app_checks_by_container,
				     std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& prometheus_by_container,
				     const uint64_t prev_flush_time_ns)
	: m_app_metrics(app_metrics),
	  m_app_metrics_limit(app_metrics_limit),
	  m_app_metrics_remaining(app_metrics_limit),
	  m_prom_conf(prom_conf),
	  m_promscrape(prom_scrape),
	  m_prom_metrics_remaining(m_prom_conf.max_metrics()),
	  m_app_checks_by_container(app_checks_by_container),
	  m_prometheus_by_container(prometheus_by_container),
	  m_prev_flush_time_ns(prev_flush_time_ns)
{
}

void app_check_emitter::emit_apps(sinsp_procinfo& procinfo,
				  sinsp_threadinfo& tinfo,
				  draiosproto::process& proc,
				  draiosproto::metrics& metrics)
{
	// Send data for each app-check for the processes in procinfo
	unsigned sent_app_checks_metrics = 0;
	unsigned filtered_app_checks_metrics = 0;
	unsigned total_app_checks_metrics = 0;
	unsigned sent_prometheus_metrics = 0;
	unsigned filtered_prometheus_metrics = 0;
	unsigned total_prometheus_metrics = 0;

	// First check if promscrape has metrics for these pids, if enabled
	if (prom_helper::c_use_promscrape.get_value())
	{
		for(auto pid: procinfo.m_program_pids)
		{
			auto export_prom = [&](int64_t pid)
			{
				if (prom_helper::c_export_fastproto->get_value())
				{
					sent_prometheus_metrics += m_promscrape->pid_to_protobuf((int)pid,
						&metrics,
						m_prom_metrics_remaining, m_prom_conf.max_metrics(),
						&filtered_prometheus_metrics, &total_prometheus_metrics);
				}
				else if (configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value())
				{
					sent_prometheus_metrics += m_promscrape->pid_to_protobuf((int)pid,
						proc.mutable_protos()->mutable_prom_info(),
						m_prom_metrics_remaining,
						m_prom_conf.max_metrics(),
						&filtered_prometheus_metrics,
						&total_prometheus_metrics);
				}
				else
				{
					sent_prometheus_metrics += m_promscrape->pid_to_protobuf((int)pid,
						proc.mutable_protos()->mutable_prometheus(),
						m_prom_metrics_remaining,
						m_prom_conf.max_metrics(),
						&filtered_prometheus_metrics,
						&total_prometheus_metrics);
				}
			};
			if (m_promscrape->pid_has_jobs((int)pid))
			{
				export_prom(pid);
			}
			// Hack: export metrics not associated with a process (as gotten from
			// remote endpoints or from Promscrape V2) under our dragent pid
			if (pid == getpid())
			{
				export_prom(0);
			}
		}
	}

	// Map of app_check data by app-check name and how long the
	// metrics have been expired to ensure we serve the most recent
	// metrics available
	std::map<std::string, std::map<int, std::shared_ptr<app_check_data>>> app_data_to_send;
	{
		const auto app_metrics = m_app_metrics.lock();
		for(auto pid: procinfo.m_program_pids)
		{
			auto datamap_it = app_metrics->find(pid);
			if(datamap_it == app_metrics->end())
				continue;
			for(const auto& app_data : datamap_it->second)
			{
				int age = (m_prev_flush_time_ns/ONE_SECOND_IN_NS) -
					  app_data.second->expiration_ts();
				app_data_to_send[app_data.first][age] = app_data.second;
			}
		}
	}

	for(const auto& app_age_map : app_data_to_send)
	{
		bool sent = false;
		for(const auto& app_data : app_age_map.second)
		{
			if(sent)
			{
				LOG_DEBUG("Skipping duplicate app metrics for %lu(%d),%s:exp in %d",
						  tinfo.m_pid, app_data.second->pid(),
						  app_age_map.first.c_str(), -app_data.first);
				continue;
			}
			LOG_DEBUG("Found app metrics for %lu(%d),%s, exp in %d", tinfo.m_pid, app_data.second->pid(),
					  app_age_map.first.c_str(), -app_data.first);
			sent = true;

#ifndef CYGWING_AGENT
			if(app_data.second->type() == app_check_data::check_type::PROMETHEUS)
			{
				static bool logged_metric = false;
				unsigned metric_count;
				if (configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value()) {
				    metric_count = app_data.second->to_protobuf(proc.mutable_protos()->mutable_prom_info(),
										m_prom_metrics_remaining,
										m_prom_conf.max_metrics());
				} else {
				    metric_count = app_data.second->to_protobuf(proc.mutable_protos()->mutable_prometheus(),
										m_prom_metrics_remaining,
										m_prom_conf.max_metrics());
				}
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
						LOG_INFO("Starting export of Prometheus metrics");
						const std::string &metricname = metrics[0].name();
						LOG_DEBUG("First prometheus metrics since agent start: pid %d: %d metrics including: %s",
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
	if(!tinfo.m_container_id.empty())
	{
		std::get<0>(m_app_checks_by_container[tinfo.m_container_id]) += sent_app_checks_metrics;
		std::get<1>(m_app_checks_by_container[tinfo.m_container_id]) += total_app_checks_metrics;
	}

	if (!prom_helper::c_use_promscrape.get_value() || (m_promscrape == nullptr) ||
		m_promscrape->emit_counters())
	{
		proc.mutable_resource_counters()->set_prometheus_sent(sent_prometheus_metrics);
		proc.mutable_resource_counters()->set_prometheus_total(total_prometheus_metrics);
		if(!tinfo.m_container_id.empty())
		{
			std::get<0>(m_prometheus_by_container[tinfo.m_container_id]) += sent_prometheus_metrics;
			std::get<1>(m_prometheus_by_container[tinfo.m_container_id]) += total_prometheus_metrics;
		}
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
	string sent_or_aggr = "sent";
	string Sent_or_Aggr = "Sent";
	if (configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value())
	{
		// With 10s flush, these numbers haven't been sent, but aggregated
		sent_or_aggr = "aggregated";
		Sent_or_Aggr = "Aggregated";
	}
	if(m_app_metrics_remaining == 0)
        {
                LOG_WARNING(
				"App checks metrics limit (%u) reached, %u %s of %u filtered, %u total",
				m_app_metrics_limit,
				m_num_app_check_metrics_sent,
				sent_or_aggr.c_str(),
				m_num_app_check_metrics_filtered,
				m_num_app_check_metrics_total);
        } else {
                LOG_DEBUG(
				"%s %u Appcheck metrics of %u filtered, %u total",
				Sent_or_Aggr.c_str(),
				m_num_app_check_metrics_sent,
				m_num_app_check_metrics_filtered,
				m_num_app_check_metrics_total);
        }

#ifndef CYGWING_AGENT
        if(m_prom_metrics_remaining == 0)
        {
                LOG_WARNING(
				"Prometheus metrics limit (%u) reached, %u %s of %u filtered, %u total",
				m_prom_conf.max_metrics(),
				m_num_prometheus_metrics_sent,
				sent_or_aggr.c_str(),
				m_num_prometheus_metrics_filtered,
				m_num_prometheus_metrics_total);
        } else {
                LOG_DEBUG(
				"%s %u Prometheus metrics of %u filtered, %u total",
				Sent_or_Aggr.c_str(),
				m_num_prometheus_metrics_sent,
				m_num_prometheus_metrics_filtered,
				m_num_prometheus_metrics_total);
        }
#endif

}
	
