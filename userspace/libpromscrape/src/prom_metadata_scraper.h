#pragma once

/**
 * A class which periodically scrapes standard Prometheus
 * endpoints for all targets monitored by Prometheus and their
 * corresponding metadata. It is periodically called by the
 * Dragent's promscrape_stats_proxy thread.
 *
 * The information collected is currently not sent to the
 * backend and is mostly for Agent CLI and logging purposes.
 */
#include "prom_job_metadata.h"
#include "interval_runner.h"

#include <mutex>
#include <string>
#include <json/json.h>

class prom_metadata_scraper
{
public:
	prom_metadata_scraper();

	typedef struct target_data
	{
		std::string url;
		std::string health;
		std::string pool;
		std::string pod;
		std::string error;
	} target_data_t;

	void process_scrape(std::string instance, const std::shared_ptr<agent_promscrape::ScrapeResult> &scrape);

	bool gather_stats_enabled();
	void enable_gather_stats(bool enable = true);
	void gather_target_stats();
	void periodic_gather_stats();

private:
	void process_targets(const Json::Value &local_targets_metadata);
	void process_metadata(const Json::Value &local_targets_metadata);

	std::mutex m_mutex;
	std::map<std::string, target_data> m_target_map;
	std::map<std::string, prom_job_metadata> m_metadata_map;

	interval_runner m_gather_interval;
	bool m_gather_stats = false;
	int m_gather_stats_count = 0;

	friend class test_helper;
};


