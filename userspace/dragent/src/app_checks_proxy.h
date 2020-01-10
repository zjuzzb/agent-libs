#pragma once

#include "app_checks_proxy_interface.h"

#include <memory>
#include <string>

#include <thread_safe_container/blocking_queue.h>
#include <metric_limits.h>
#include <prometheus.h>
#include "watchdog_runnable.h"

struct app_check_request
{
	std::vector<app_process> processes;
	std::vector<prom_process> prom_procs;
	const prometheus_conf* conf;
};


class app_checks_proxy : public dragent::watchdog_runnable, public app_checks_proxy_interface {
public:
	explicit app_checks_proxy(metric_limits::sptr_t metric_limits, bool threaded):
		dragent::watchdog_runnable("app_checks_proxy"),
		m_threaded(threaded),
		m_outqueue("/sdc_app_checks_in", posix_queue::SEND, 1),
		m_inqueue("/sdc_app_checks_out", posix_queue::RECEIVE, 2),
		m_metric_limits(std::move(metric_limits)),
		m_request_queue(4) // chosen by a fair dice roll
	{}

	bool have_metrics_for_pid(uint64_t pid) const override;
	bool have_prometheus_metrics_for_pid(uint64_t pid, uint64_t flush_time_sec) const override;
	bool have_app_check_metrics_for_pid(uint64_t pid, uint64_t flush_time_sec, const std::string& name) const override;
	const metric_map_t& get_all_metrics() const override {
		return m_app_metrics;
	}
	void send_get_metrics_cmd(std::vector<app_process> processes,
				  std::vector<prom_process> prom_procs, const prometheus_conf* conf) override;
	void refresh_metrics(uint64_t flush_time_sec, uint64_t timeout_sec) override;

	void do_run() override;

private:
	void send_get_metrics_cmd_sync(const std::vector<app_process>& processes,
				  const std::vector<prom_process>& prom_procs, const prometheus_conf &conf);
	raw_metric_map_t read_metrics(const metric_limits::sptr_t& ml = nullptr, uint64_t timeout_sec=0);
	void refresh_metrics_sync(uint64_t flush_time_sec, uint64_t timeout_sec);

	const bool m_threaded;
	posix_queue m_outqueue;
	posix_queue m_inqueue;
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;

	metric_limits::sptr_t m_metric_limits;
	metric_map_t m_app_metrics;
	thread_safe_container::blocking_queue<app_check_request> m_request_queue;

	// the only one currently defined and the only one we support
	static constexpr const uint8_t PROTOCOL_VERSION = 1;

	// sanity checks, we could support up to 4 GB compressed/uncompressed
	// size but that's rather excessive and probably indicates a bug
	// MAXSIZE in sdchecks.py is 3 MB so in theory we never exceed this
	static constexpr const size_t MAX_COMPRESSED_SIZE = 4UL << 20u;
	static constexpr const size_t MAX_UNCOMPRESSED_SIZE = 100UL << 20u;
};
