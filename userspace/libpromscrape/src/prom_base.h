#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>

#include "agent-prom.grpc.pb.h"
#include "agent-prom.pb.h"
#include "draios.pb.h"
#include "promscrape_conf.h"
#include "limits/metric_limits.h"
#include "interval_runner.h"
#include "prom_grpc_iface.h"
#include "prom_job.h"
#include <thread_safe_container/blocking_queue.h>
#include <mutex>
#include <json/json.h>

class prom_infra_iface;

class prom_base
{
public:
	// Map from process-id to job-ids
	typedef std::map<int, std::list<int64_t>> prom_pid_map_t;
	// Map from job_id to prom_job
	typedef std::map<int64_t, prom_job> prom_jobid_map_t;

	/**
	 * There are a few hacks in here related to 10s flush. Hopefully
	 * those can go away if/when we get support for a callback that
	 * lets promscrape override the outgoing protobuf Hack to get
	 * dynamic interval from dragent without adding dependency
	 * 
	 */
	typedef std::function<int()> interval_cb_t;

	/**
	 * Other hack to let analyzer flush loop know if it can populate
	 * the prometheus metric counters (otherwise promscrape will be
	 * managing them instead)
	 * 
	 */
	bool emit_counters() const;

	// jobs that haven't been used for this long will be pruned.
	const int job_prune_time_s = 15;

	explicit prom_base(metric_limits::sptr_t ml, const promscrape_conf &prom_conf, bool threaded, interval_cb_t interval_cb, std::unique_ptr<prom_streamgrpc_iface> grpc_start);

	virtual ~prom_base()
	{
	}

	/**
	 * This method needs to be called from the main thread on a
	 * regular basis. With threading enabled, it just updates the
	 * current timestamp. Without threading, it will also call into
	 * next_th().
	 * 
	 */
	void next(uint64_t ts);

	/**
	 * This method manages the GRPC connections and processes the
	 * queues and incoming scrape messages. Only needs to be called
	 * explicitly if threading is enabled, on its own thread.
	 *
	 */
	virtual void next_th() = 0;

	/**
	 * Sends config to the GRPC stream, received by the Prometheus
	 * process. Its a no-op in V2 as it does its own service
	 * discovery. It needs to be called only when the caller is
	 * using the scraper in a single-threaded application.
	 * 
	 */
	virtual void sendconfig(const std::vector<prom_process> &prom_procs)
	{
	}


	/**
	 * Check if a given pid has jobs.
	 * 
	 */
	bool pid_has_jobs(int pid);

	/**
	 * Check if a given pid has metrics.
	 */
	bool pid_has_metrics(int pid);


	/**
	 * Called by aggregator to populate metrics protobuf and gets 
	 * called once per flush interval and only when 10s flush is
	 * enabled.
	 * 
	 */
	std::shared_ptr<draiosproto::metrics> metrics_request_callback();

	/**
	 * Packs prometheus metrics for the given pid into the protobuf
	 * "proto" by calling to_protobuf() for every job.
	 * 
	 * @param <metric> either a draiosproto::app_metric or
	 *  	  prometheus metric.
	 * @param pid - The pid for which the protobuf is created.
	 * @param limit - The limit of metrics that can still be added
	 *  			to the protobuf.
	 * @param max_limit - ??
	 * @param [out[filtered - The total number of metrics that
	 *  	  passed the filter.
	 * @param [out]total - The total number of metrics before
	 *  	  filtering.
	 * @param callback - Boolean to indicate if the method is called
	 *  			   from the aggregator callback or not.
	 * @return unsigned int
	 */
	template<typename metric>
	unsigned int pid_to_protobuf(int pid, metric *proto,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total, bool callback = false);

	void set_infra_state(prom_infra_iface *is) { m_infra_state = is; }

	typedef std::function<void(std::shared_ptr<draiosproto::raw_prometheus_metrics> msg)> raw_bypass_cb_t;
	void set_raw_bypass_callback(raw_bypass_cb_t cb) { m_bypass_cb = cb; }

	void set_allow_bypass(bool allow) { m_allow_bypass = allow; }
	void periodic_log_summary();

protected:
	virtual void handle_result(agent_promscrape::ScrapeResult &result) = 0;
	virtual void prune_jobs(uint64_t ts) = 0;
	virtual void delete_job(int64_t job_id);
	virtual void reset();
	bool started();
	void try_start();

	bool m_threaded;
	uint64_t m_boot_ts;
	std::atomic<uint64_t> m_next_ts;
	uint64_t m_last_ts;
	uint64_t m_last_prune_ts;
	bool m_start_failed;

	std::string m_sock;
    std::unique_ptr<prom_streamgrpc_iface> m_grpc_start;

	promscrape_conf m_prom_conf;
	metric_limits::sptr_t m_metric_limits;
    prom_infra_iface *m_infra_state = nullptr;
	bool m_allow_bypass;

	// A single mutex to protect all stores
	std::recursive_mutex m_map_mutex;
	prom_jobid_map_t m_jobs;
	prom_pid_map_t m_pids;

	raw_bypass_cb_t m_bypass_cb;
private:
	void start();
	void log_summary();
	void clear_stats();

	interval_runner m_start_interval;
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_start_conn;

	interval_cb_t m_interval_cb;
	uint64_t m_last_proto_ts;

	// Mutex to protect m_export_pids
	std::mutex m_export_pids_mutex;
	std::set<int> m_export_pids;    // Populated by pid_to_protobuf for 10s flush callback.

	bool m_emit_counters;

	interval_runner m_log_interval;

	friend class prom_v1_helper;
	friend class prom_v2_helper;
};

