#include<memory>
#include<string>
#include<map>

#include "agent-prom.pb.h"
#include "prom_scrape_helper.h"

namespace prom_scrape_helper
{

/**
 * Helper to create a Scrape result for Prometheus Scraper
 * testing.
 */
void scrape_maker::add_result(int64_t job_id, int64_t timestamp, const std::string &url)
{
	res->set_job_id(job_id);
	res->set_timestamp(timestamp);
	res->set_url(url);
}
void scrape_maker::add_metasample(const std::string &name, double value)
{
	auto meta_sample = res->add_meta_samples();
	meta_sample->set_metric_name(name);
	meta_sample->set_value(value);
}
void scrape_maker::add_sample(const std::string &name, double value,
	agent_promscrape::Sample::LegacyMetricType lmt,
	agent_promscrape::Sample::RawMetricType rmt,
	const label_map_t &label_map)
{
	auto sample = res->add_samples();
	sample->set_metric_name(name);
	sample->set_value(value);
	sample->set_legacy_metric_type(lmt);
	sample->set_raw_metric_type(rmt);
	for (auto it = label_map.begin(); it != label_map.end(); it++)
	{
		auto label = sample->add_labels();
		label->set_name(it->first);
		label->set_value(it->second);
	}
}

void scrape_maker::add_source_label(const std::string &name, const std::string &value)
{
	auto label = res->add_source_labels();
	label->set_name(name);
	label->set_value(value);
}

void build_sample_scrape(scrape_maker &scraper, const std::string &url, const std::string &job_name)
{
	scraper.add_source_label("container_id", "c1");
	scraper.add_source_label("pod_id", "p1");
	scraper.add_source_label("container_name", "ctr");
	scraper.add_source_label("sysdig_bypass", "false");
	scraper.add_source_label("sysdig_omit_source", "");

	scraper.add_metasample("scrape_samples_scraped", 2.0);
	scraper.add_metasample("scrape_samples_post_metric_relabeling", 2.0);
	scraper.add_metasample("scrape_series_added", 2.0);

	label_map_t label_map;
	label_map["instance"] = url;
	label_map["job"] = job_name;

	scraper.add_sample("sample1", 1.0, agent_promscrape::Sample::MT_RAW, agent_promscrape::Sample::RAW_COUNTER, label_map);
	scraper.add_sample("sample2", 2.0, agent_promscrape::Sample::MT_RAW, agent_promscrape::Sample::RAW_COUNTER, label_map);
	scraper.add_sample("sample3", 3.0, agent_promscrape::Sample::MT_LEGACY_GAUGE, agent_promscrape::Sample::RAW_COUNTER, label_map);
	scraper.add_sample("sample4", 4.0, agent_promscrape::Sample::MT_LEGACY_BUCKET, agent_promscrape::Sample::RAW_COUNTER, label_map);
}

}  // namespace prom_scrape_helper
