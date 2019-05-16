#pragma once
#include <unordered_map>
#include "prometheus.h"

/**
 * Does the work of emitting the app check metrics of processes during the scope of a SINGLE
 * flush.
 *
 * emit_apps must be invoked on each process which is inteded to have its app metrics
 * flushed.
 */
class app_check_emitter {
public:
	app_check_emitter(app_checks_proxy::metric_map_t& app_metrics,
		    const uint16_t app_metrics_limit,
		    const prometheus_conf& prom_conf,
		    std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& app_checks_by_container,
		    std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& prometheus_by_container,
		    const uint64_t prev_flush_time_ns);

	/**
	 * emit the app metrics for a single process/thread
	 */
	void emit_apps(sinsp_procinfo& procinfo,
		       sinsp_threadinfo& tinfo,
		       draiosproto::process& proc);

	/**
	 * log the results of an entire flush. Will log warning of some results were
	 * truncated
	 */
	void log_result();

private:
	app_checks_proxy::metric_map_t& m_app_metrics;
	const uint16_t m_app_metrics_limit;
	uint16_t m_app_metrics_remaining;
	const prometheus_conf& m_prom_conf;
	uint16_t m_prom_metrics_remaining;
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& m_app_checks_by_container;
        std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& m_prometheus_by_container;
	const uint64_t m_prev_flush_time_ns;

	unsigned m_num_app_check_metrics_sent = 0;
        unsigned m_num_app_check_metrics_filtered = 0;
        unsigned m_num_app_check_metrics_total = 0;
        unsigned m_num_prometheus_metrics_sent = 0;
        unsigned m_num_prometheus_metrics_filtered = 0;
        unsigned m_num_prometheus_metrics_total = 0;

};
