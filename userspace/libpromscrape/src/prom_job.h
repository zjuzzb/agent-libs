#pragma once

#include "agent-prom.grpc.pb.h"
#include "agent-prom.pb.h"
#include "draios.pb.h"
#include "limits/metric_limits.h"

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>

class prom_infra_iface;

typedef struct metric_stats
{
	metric_stats() : scraped(0),
		job_filter_dropped(0),
		over_job_limit(0),
		global_filter_dropped(0),
		sent(0)
	{
	}
	int scraped;
	int job_filter_dropped;
	int over_job_limit;
	int global_filter_dropped;
	int sent;
} metric_stats_t;

class prom_job
{
public:
	prom_job(const std::string &url);

	typedef std::map<std::string, std::string> tag_map_t;

	template<typename metric>
	unsigned int to_protobuf(metric *proto,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr);

	std::shared_ptr<draiosproto::raw_prometheus_metrics> to_bypass_protobuf(uint64_t next_ts, prom_infra_iface *infra_ptr);

	void handle_result(metric_limits::sptr_t metric_limits,
		agent_promscrape::ScrapeResult &result,
		bool allow_raw,
		uint64_t last_ts,
		prom_infra_iface *infra_ptr);

	/**
	 * TODO: The below getters and setters are required
	 * until prom_job is split to prom_job_v1 and prom_job_v2
	 * and to_protobuf is refactored.
	 */
	std::string url() const { return m_url; }

	int pid() const { return m_pid; }
	void set_pid(int pid) { m_pid = pid; }

	std::string container_id() const { return m_container_id; }
	void set_container_id(const std::string &container_id) { m_container_id = container_id; }

	uint64_t config_ts() const { return m_config_ts; }
	void set_config_ts(int ts) { m_config_ts = ts; }

	tag_map_t add_tags() const { return m_add_tags; }
	void set_tags(const tag_map_t &tags) { m_add_tags = tags; }

	bool stale() const { return m_stale; }
	void set_stale(bool stale) { m_stale = stale; }

	uint64_t data_ts() const { return m_data_ts; }
	bool bypass_limits() const { return m_bypass_limits; }
	bool omit_source() const { return m_omit_source; }

	bool has_metrics() { return m_result_ptr != nullptr; }

	int get_total_filtered_metrics() const;
	int get_total_unsent_metrics() const;
	void log_summary(int &unsent_global, int &unsent_job);
	void clear();

private:

	void process_samples(metric_limits::sptr_t metric_limits,
		agent_promscrape::ScrapeResult &result,
		bool allow_raw);
	std::string get_instance();
	void process_host_info(prom_infra_iface *infra_ptr);

	unsigned int to_protobuf_imp(draiosproto::prom_metrics *pb, bool enforce_limits,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr);

	std::string m_url;
	int m_pid;
	std::string m_container_id;
	uint64_t m_config_ts;
	uint64_t m_data_ts;
	uint64_t m_last_total_samples;
	tag_map_t m_add_tags;
	bool m_bypass_limits;
	bool m_stale;
	bool m_omit_source;     // Don't send source_metadata
	std::shared_ptr<agent_promscrape::ScrapeResult> m_result_ptr;
	metric_stats_t m_raw_stats;
	metric_stats_t m_calc_stats;
	int m_count_over_global_limit;

	friend class prom_job_helper;
};




