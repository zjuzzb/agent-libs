#pragma once

#include<memory>
#include<string>
#include<map>

#include "agent-prom.pb.h"

namespace prom_scrape_helper
{

typedef std::map<std::string, std::string> label_map_t;
/**
 * Helper to create a Scrape result for Prometheus Scraper
 * testing.
 */
class scrape_maker
{
public:
	scrape_maker(agent_promscrape::ScrapeResult *r) :
		res(r)
	{
	}

	void add_result(int64_t job_id, int64_t timestamp, const std::string &url);

	void add_metasample(const std::string &name, double value);

	void add_sample(const std::string &name, double value,
		agent_promscrape::Sample::LegacyMetricType lmt,
		agent_promscrape::Sample::RawMetricType rmt,
		const label_map_t &label_map);

	void add_source_label(const std::string &name, const std::string &value);

private:
	agent_promscrape::ScrapeResult *res;
};

void build_sample_scrape(scrape_maker &scraper, const std::string &url, const std::string &job_name);

}  // namespace prom_scrape_helper
