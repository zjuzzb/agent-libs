#include <memory>

#include "common_logger.h"
#include "promscrape_conf.h"
#include "prom_helper.h"
#include "type_config.h"
#include "Poco/URI.h"
#include "configuration_manager.h"
#include "Poco/Exception.h"
#include <json/json.h>
#include "prom_job.h"
#include "prom_base.h"
#include "prom_infra_iface.h"
#include "stream_grpc_status.h"
#include "utils.h"
#include "wall_time.h"

COMMON_LOGGER();
using namespace prom_helper;

prom_base::prom_base(metric_limits::sptr_t ml,
	const promscrape_conf &prom_conf,
	bool threaded,
	interval_cb_t interval_cb,
	std::unique_ptr<prom_streamgrpc_iface> grpc_start):
	m_threaded(threaded),
	m_boot_ts(0),
	m_next_ts(0),
	m_last_ts(0),
	m_last_prune_ts(0),
	m_start_failed(false),
	m_sock(c_promscrape_sock.get_value()),
	m_grpc_start(std::move(grpc_start)),
	m_prom_conf(prom_conf),
	m_metric_limits(ml),
	m_infra_state(nullptr),
	m_allow_bypass(false),
	m_start_interval(c_promscrape_connect_interval.get_value() * get_one_second_in_ns()),
	m_interval_cb(interval_cb),
	m_last_proto_ts(0),
	m_emit_counters(true),
	m_log_interval(c_promscrape_stats_log_interval.get_value() * get_one_second_in_ns())
{
}

bool prom_base::started()
{
	return m_grpc_start != nullptr && m_grpc_start->started();
}

void prom_base::start()
{
	agent_promscrape::Empty empty;

	LOG_INFO("promscrape starting");

	auto callback = [this](streaming_grpc::Status status, agent_promscrape::ScrapeResult &result)
	{
			if (status == streaming_grpc::OK)
			{
				handle_result(result);
				return;
			}

			if (status == streaming_grpc::ERROR)
			{
				LOG_ERROR("promscrape start grpc failed");
			}
			else if (status == streaming_grpc::SHUTDOWN)
			{
				LOG_ERROR("promscrape grpc shut down");
			}
			else
			{
				LOG_ERROR("promscrape received unknown status %d", (int)status);
			}
			m_start_failed = true;
	};

	if (m_grpc_start)
	{ 
        m_grpc_start->start_stream_connection(m_boot_ts, callback);
	} else {
        LOG_ERROR("No stream connection object provided to Promscrape \n");
	}
}

void prom_base::try_start()
{
	if (started())
	{
		return;
	}
	if (!m_boot_ts)
	{
		m_boot_ts = wall_time::nanoseconds();
	}

	if (elapsed_s(m_boot_ts, wall_time::nanoseconds()) < c_promscrape_connect_delay.get_value())
	{
		return;
	}
	m_start_interval.run([this]()
	{
			start();
	}, wall_time::nanoseconds());
}

void prom_base::delete_job(int64_t job_id)
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);

	auto it = m_jobs.find(job_id);
	if (it == m_jobs.end())
	{
		LOG_WARNING("Tried deleting missing job %" PRId64, job_id);
		return;
	}

	// Remove job from pid-jobs list
	LOG_DEBUG("Deleting scrape job %" PRId64 ", pid %d", it->first, it->second.pid());

	auto pidmap_it = m_pids.find(it->second.pid());
	if (pidmap_it == m_pids.end())
	{
		LOG_WARNING("pid %d not found in pidmap for job %" PRId64, it->second.pid(), it->first);
	}
	else
	{
		pidmap_it->second.remove(it->first);
		if (pidmap_it->second.empty())
		{
			// No jobs left for pid
			LOG_DEBUG("no scrape jobs left for pid %d, removing", it->second.pid());
			m_pids.erase(pidmap_it);
		}
	}
	// Remove job from jobs map
	m_jobs.erase(it);
}

void prom_base::reset()
{
	LOG_INFO("resetting connection");
	m_start_failed = false;
	if (m_grpc_start) {
        m_grpc_start->reset();
	}
}

/* public methods */

bool prom_base::emit_counters() const
{
	if (!c_use_promscrape.get_value() ||
		!(configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value()))
	{
		return true;
	}
	return m_emit_counters;
}

void prom_base::next(uint64_t ts)
{
	m_next_ts = ts;

	if (!m_threaded)
	{
		next_th();
	}
}

bool prom_base::pid_has_jobs(int pid)
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
	return m_pids.find(pid) != m_pids.end();
}

bool prom_base::pid_has_metrics(int pid)
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
	const auto pidmap_it = m_pids.find(pid);
	if (pidmap_it == m_pids.end())
	{
		return false;
	}
	for (uint64_t job_id : pidmap_it->second)
	{
		auto it = m_jobs.find(job_id);
		if ((it != m_jobs.end()) && it->second.has_metrics())
		{
			return true;
		}
	}
	return false;
}


std::shared_ptr<draiosproto::metrics> prom_base::metrics_request_callback()
{
	unsigned int sent = 0;
	unsigned int remaining = m_prom_conf.max_metrics();
	unsigned int filtered = 0;
	unsigned int total = 0;
	std::shared_ptr<draiosproto::metrics> metrics = std::make_shared<draiosproto::metrics>();

	if (!c_export_fastproto->get_value())
	{
		// Shouldn't get here yet
		LOG_INFO("metrics callback not yet supported for per-process export");

		metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_sent(0);
		metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_total(0);
		return metrics;
	}

	std::set<int> export_pids;
	{
		std::lock_guard<std::mutex> lock(m_export_pids_mutex);
		export_pids = std::move(m_export_pids);
		m_export_pids.clear();
		// Add all stale pids
		for (const auto &job : m_jobs)
		{
			if (job.second.stale())
			{
				LOG_DEBUG("Found stale job %" PRId64 " for pid %d", job.first, job.second.pid());
				export_pids.insert(job.second.pid());
			}
		}
	}

	for (int pid : export_pids)
	{
		LOG_DEBUG("callback: exporting pid %d", pid);
		sent += pid_to_protobuf(pid, metrics.get(), remaining, m_prom_conf.max_metrics(),
			&filtered, &total, true);
	}

	metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_sent(sent);
	metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_total(total);
	if (remaining == 0)
	{
		LOG_WARNING("Prometheus metrics limit (%u) reached, %u sent of %u filtered, %u total",
			m_prom_conf.max_metrics(), sent, filtered, total);
	}
	else
	{
		LOG_DEBUG("Sent %u Prometheus metrics of %u filtered, %u total",
			sent, filtered, total);
	}

	return metrics;
}

template<typename metric>
unsigned int prom_base::pid_to_protobuf(int pid, metric *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback)
{
	unsigned int num_metrics = 0;

	if (!callback)
	{
		if (can_use_metrics_request_callback())
		{
			// Add pid to export set. The metrics_request_callback will trigger the
			// actual population of the protobuf by calling into this method with the
			// callback bool set to true
			LOG_DEBUG("adding pid %d to export set", pid);

			std::lock_guard<std::mutex> lock(m_export_pids_mutex);
			m_export_pids.emplace(pid);
			m_emit_counters = false;
			return 0;
		}
		else if (configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value())
		{
			// Hack to only write protobufs once per interval, where interval is the
			// negotiated interval between agent and collector
			// XXX: The new aggregator callback doesn't work yet for per-process metrics.
			// Once it does we can use that instead, like we do for the fastproto case above
			// See SMAGENT-2293
			int interval = (m_interval_cb != nullptr) ? m_interval_cb() : 10;
			// Timestamp will be the same for different pids in same flush cycle
			if ((m_next_ts > m_last_proto_ts) &&
				(m_next_ts < (m_last_proto_ts + (interval * get_one_second_in_ns()) -
							  (get_one_second_in_ns() / 2))))
			{
				LOG_DEBUG("skipping protobuf");
				m_emit_counters = false;
				return num_metrics;
			}
			m_emit_counters = true;
			m_last_proto_ts = m_next_ts;
		}
	}

	{
		std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
		auto it = m_pids.find(pid);
		if (it == m_pids.end())
		{
			return num_metrics;
		}

		for (auto job_id : it->second)
		{
			LOG_DEBUG("pid %d: have job %" PRId64, pid, job_id);
			auto job = m_jobs.at(job_id);
			num_metrics += job.to_protobuf(proto, limit, max_limit, filtered, total, m_infra_state);
			if (job.stale())
			{
				delete_job(job_id);
			}
		}
	}
	return num_metrics;
}

template unsigned int prom_base::pid_to_protobuf<draiosproto::app_info>(int pid, draiosproto::app_info *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback);
template unsigned int prom_base::pid_to_protobuf<draiosproto::prometheus_info>(int pid, draiosproto::prometheus_info *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback);
template unsigned int prom_base::pid_to_protobuf<draiosproto::metrics>(int pid, draiosproto::metrics *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback);

void prom_base::periodic_log_summary()
{
	m_log_interval.run([this]()
	{
			log_summary();
			clear_stats();
	}, wall_time::nanoseconds());
}

void prom_base::log_summary()
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
	int unsent_global = 0;
	int unsent_job = 0;

	LOG_INFO("Prometheus timeseries statistics, %lu endpoints", m_jobs.size());
	for (auto it = m_jobs.begin(); it != m_jobs.end(); ++it)
	{
		int t_unsent_global = 0;
		int t_unsent_job = 0;
		it->second.log_summary(t_unsent_global, t_unsent_job);
		unsent_global += t_unsent_global;
		unsent_job += t_unsent_job;
	}

	if (unsent_global)
	{
		LOG_WARNING("Prometheus metrics limit (%u) reached. %d timeseries not sent"
			" to avoid data inconsistencies, see preceding info logs for details",
			m_prom_conf.max_metrics(), unsent_global);
	}
	if (unsent_job)
	{
		LOG_WARNING("Prometheus job sample limit reached. %d timeseries not sent"
			" to avoid data inconsistencies, see preceding info logs for details",
			unsent_job);
	}
}

void prom_base::clear_stats()
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);

	for (auto it = m_jobs.begin(); it != m_jobs.end(); ++it)
	{
		it->second.clear();
	}
}


