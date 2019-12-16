#pragma once

#include <unordered_map>

#include <app_checks.h>

/**
 * @brief Abstract base class for communicating with app checks
 */
class app_checks_proxy_interface
{
public:
	/**
	 * @brief the type of the metrics actually received
	 *
	 * This is a two-level map, indexed by pid and app_check name
	 */
	using raw_metric_map_t = std::unordered_map<int, std::map<std::string, std::shared_ptr<app_check_data>>>;

	/**
	 * @brief the type of the metrics we hand out to consumers of this interface
	 */
	using metric_map_t = raw_metric_map_t;

	/**
	 * @brief Do we have any metrics for `pid` in the last sample?
	 */
	virtual bool have_metrics_for_pid(uint64_t pid) const = 0;

	/**
	 * @brief Do we have up to date Prometheus metrics for `pid`?
	 *
	 * @return true if the cache has Prometheus metrics for `pid` that are
	 * still valid at Unix timestamp `flush_time_sec`, false otherwise
	 */
	virtual bool have_prometheus_metrics_for_pid(uint64_t pid, uint64_t flush_time_sec) const = 0;

	/**
	 * @brief Do we have up to date app check `name` metrics for `pid`?
	 *
	 * @return true if the cache for `pid` has app check results for the
	 * `name` app check that are still valid at Unix timestamp `flush_time_sec`,
	 * false otherwise
	 */
	virtual bool have_app_check_metrics_for_pid(uint64_t pid, uint64_t flush_time_sec, const std::string& name) const = 0;

	/**
	 * @brief Get all cached metrics
	 *
	 * This method should be fast and not perform any I/O
	 */
	virtual const metric_map_t& get_all_metrics() const = 0;

	/**
	 * @brief Send a request to sdchecks
	 * @param processes discovered app checks
	 * @param prom_procs discovered Prometheus exporters
	 * @param conf Prometheus config
	 *
	 * This method should be fast and not perform any I/O
	 * It should enqueue the request to be sent by e.g. a background
	 * thread instead
	 */
	virtual void send_get_metrics_cmd(
		std::vector<app_process> processes,
		std::vector<prom_process> prom_procs,
		const prometheus_conf* conf) = 0;

	/**
	 * @brief Refresh metric cache synchronously, if needed
	 * @param flush_time_sec current time (Unix timestamp)
	 * @param timeout_sec timeout for the refresh
	 *
	 * If a synchronous refresh is not needed (because e.g. it happens
	 * in a separate thread), this method should do nothing
	 */
	virtual void refresh_metrics(uint64_t flush_time_sec, uint64_t timeout_sec) = 0;
};
