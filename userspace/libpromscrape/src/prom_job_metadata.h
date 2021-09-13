#pragma once

/**
 * A class which manages the metadata of a given URL/Job.
 * Note that a Job has a 1:1 mapping with a URL.
 */

#include <memory>
#include <string>
#include <map>

#include "agent-prom.pb.h"

#include <json/json.h>

typedef struct metric_metadata
{
	metric_metadata() : timeseries(0)
	{
	}
	std::string type;
	std::string help;
	std::string unit;
	int timeseries;
} metric_metadata_t;

class prom_job_metadata
{
public:
	prom_job_metadata(const std::string &url) : m_url(url)
	{
	}

	void process_scrape(const std::shared_ptr<agent_promscrape::ScrapeResult> &scrape_result);
	void process_metric_metadata(const Json::Value &metric);

	std::map<std::string, metric_metadata_t> get_metadata() { return m_metric_metadata; }

private:
	std::string m_url;
	std::map<std::string, metric_metadata_t> m_metric_metadata;
};



