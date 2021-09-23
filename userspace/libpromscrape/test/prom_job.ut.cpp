#include <memory>
#include <string>
#include <vector>
#include <map>

#include "prom_job.h"
#include "prom_scrape_helper.h"
#include "prom_helper.h"

#include <gtest.h>

using namespace prom_scrape_helper;

namespace
{
typedef std::map<std::string, std::string> label_map_t;
uint32_t DEFAULT_CACHE_SIZE = 10000;
}

class prom_job_helper
{
public:
	prom_job_helper(prom_job *job) : m_job(job)
	{
	}

	std::string url()
	{
		return m_job->m_url;
	}

	int64_t timestamp()
	{
		return m_job->m_result_ptr->timestamp();
	}

	double get_sample_value(const std::string &name)
	{
		for (const auto &sample : m_job->m_result_ptr->samples())
		{
			if (sample.metric_name() == name)
			{
				return sample.value();
			}
		}
		return 0.0;
	}

	double get_meta_sample_value(const std::string &name)
	{
		for (const auto &sample : m_job->m_result_ptr->meta_samples())
		{
			if (sample.metric_name() == name)
			{
				return sample.value();
			}
		}
		return 0.0;
	}

	std::string get_source_label_value(const std::string &name)
	{
		for (const auto &label : m_job->m_result_ptr->source_labels())
		{
			if (label.name() == name)
			{
				return label.value();
			}
		}
		return "";
	}

	metric_stats_t raw_stats()
	{
		return m_job->m_raw_stats;
	}

	metric_stats_t calc_stats()
	{
		return m_job->m_calc_stats;
	}

	uint64_t last_total_samples()
	{
		return m_job->m_last_total_samples;
	}
private:
	prom_job *m_job;
};

//Test that the result is parsed correctly if metric_limits is passed
//with no global filter.
TEST(prom_job_test, handle_result_metrics_with_no_filter)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scraper(&res);
	const std::string url = "100.10.20.30:105";

	scraper.add_result(101, 202, url);
	build_sample_scrape(scraper, url, "");

	prom_job job(url);
	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	job.handle_result(ml, res, true, 1, nullptr);

	prom_job_helper t(&job);
	EXPECT_EQ(t.url(), url);
	EXPECT_EQ(t.timestamp(), 202);
	EXPECT_EQ(t.get_source_label_value("container_id"), "c1");
	EXPECT_EQ(t.get_source_label_value("pod_id"), "p1");
	EXPECT_EQ(t.get_source_label_value("container_name"), "ctr");

	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_scraped"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_post_metric_relabeling"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_series_added"), 2.0);

	EXPECT_EQ(t.get_sample_value("sample1"), 1.0);
	EXPECT_EQ(t.get_sample_value("sample2"), 2.0);
	EXPECT_EQ(t.get_sample_value("sample3"), 3.0);
	EXPECT_EQ(t.get_sample_value("sample4"), 4.0);

	EXPECT_EQ(t.last_total_samples(), 4);
	EXPECT_EQ(t.raw_stats().scraped, 2);
	EXPECT_EQ(t.calc_stats().scraped, 2);
}

//Test that the result is parsed correctly if bypass_limits
//is set to true.
TEST(prom_job_test, handle_result_bypass)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scraper(&res);
	const std::string url = "100.10.20.30:105";

	scraper.add_result(101, 202, url);
	build_sample_scrape(scraper, url, "");
	prom_helper::set_label_value(res.mutable_source_labels(), "sysdig_bypass", "true");

	prom_job job(url);
	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	job.handle_result(ml, res, true, 1, nullptr);

	prom_job_helper t(&job);
	EXPECT_EQ(t.url(), url);
	EXPECT_EQ(t.timestamp(), 202);
	EXPECT_EQ(t.get_source_label_value("container_id"), "c1");
	EXPECT_EQ(t.get_source_label_value("pod_id"), "p1");
	EXPECT_EQ(t.get_source_label_value("container_name"), "ctr");

	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_scraped"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_post_metric_relabeling"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_series_added"), 2.0);

	EXPECT_EQ(t.get_sample_value("sample1"), 1.0);
	EXPECT_EQ(t.get_sample_value("sample2"), 2.0);
	EXPECT_EQ(t.get_sample_value("sample3"), 3.0);
	EXPECT_EQ(t.get_sample_value("sample4"), 4.0);

	EXPECT_EQ(t.last_total_samples(), 4);
	EXPECT_EQ(t.raw_stats().scraped, 2);
	EXPECT_EQ(t.calc_stats().scraped, 2);
}

//Test that the result is parsed correctly if
//some global filters are applied.
TEST(prom_job_test, handle_result_with_filter)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scraper(&res);
	const std::string url = "100.10.20.30:105";

	scraper.add_result(101, 202, url);

	scraper.add_source_label("container_id", "c1");
	scraper.add_source_label("pod_id", "p1");
	scraper.add_source_label("container_name", "ctr");
	scraper.add_source_label("sysdig_bypass", "false");
	scraper.add_source_label("sysdig_omit_source", "");

	scraper.add_metasample("scrape_samples_scraped", 4.0);
	scraper.add_metasample("scrape_samples_post_metric_relabeling", 2.0);
	scraper.add_metasample("scrape_series_added", 2.0);

	label_map_t label_map;
	label_map["instance"] = url;

	scraper.add_sample("sample1.one", 1.0, agent_promscrape::Sample::MT_RAW, agent_promscrape::Sample::RAW_COUNTER, label_map);
	scraper.add_sample("allowed2.one", 2.0, agent_promscrape::Sample::MT_RAW, agent_promscrape::Sample::RAW_COUNTER, label_map);
	scraper.add_sample("sample3.one", 3.0, agent_promscrape::Sample::MT_LEGACY_GAUGE, agent_promscrape::Sample::RAW_COUNTER, label_map);
	scraper.add_sample("allowed4.one", 4.0, agent_promscrape::Sample::MT_LEGACY_BUCKET, agent_promscrape::Sample::RAW_COUNTER, label_map);

	prom_job job(url);
	filter_vec_t filters({ { "sample1.*", false }, { "sample3.*", false } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	job.handle_result(ml, res, true, 1, nullptr);

	prom_job_helper t(&job);
	EXPECT_EQ(t.url(), url);
	EXPECT_EQ(t.timestamp(), 202);
	EXPECT_EQ(t.get_source_label_value("container_id"), "c1");
	EXPECT_EQ(t.get_source_label_value("pod_id"), "p1");
	EXPECT_EQ(t.get_source_label_value("container_name"), "ctr");

	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_scraped"), 4.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_post_metric_relabeling"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_series_added"), 2.0);

	//Sample 1&3 filtered.
	EXPECT_EQ(t.get_sample_value("sample1.one"), 0.0);
	EXPECT_EQ(t.get_sample_value("allowed2.one"), 2.0);

	EXPECT_EQ(t.get_sample_value("sample3.one"), 0.0);
	EXPECT_EQ(t.get_sample_value("allowed4.one"), 4);

	EXPECT_EQ(t.last_total_samples(), 4);
	metric_stats_t raw_stats = t.raw_stats();
	EXPECT_EQ(raw_stats.scraped, 4);
	EXPECT_EQ(raw_stats.global_filter_dropped, 1);

	metric_stats_t calc_stats = t.calc_stats();
	EXPECT_EQ(calc_stats.scraped, 2);
	EXPECT_EQ(calc_stats.global_filter_dropped, 1);
}

//Test that the result is parsed correctly if
//no metric limits are applied.
TEST(prom_job_test, handle_result_with_no_metrics)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scraper(&res);
	const std::string url = "100.10.20.30:105";

	scraper.add_result(101, 202, url);
	build_sample_scrape(scraper, url, "");

	prom_job job(url);
	metric_limits::sptr_t ml = nullptr;

	job.handle_result(ml, res, true, 1, nullptr);

	prom_job_helper t(&job);
	EXPECT_EQ(t.url(), url);
	EXPECT_EQ(t.timestamp(), 202);
	EXPECT_EQ(t.get_source_label_value("container_id"), "c1");
	EXPECT_EQ(t.get_source_label_value("pod_id"), "p1");
	EXPECT_EQ(t.get_source_label_value("container_name"), "ctr");

	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_scraped"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_samples_post_metric_relabeling"), 2.0);
	EXPECT_EQ(t.get_meta_sample_value("scrape_series_added"), 2.0);

	EXPECT_EQ(t.get_sample_value("sample1"), 1.0);
	EXPECT_EQ(t.get_sample_value("sample2"), 2.0);
	EXPECT_EQ(t.get_sample_value("sample3"), 3.0);
	EXPECT_EQ(t.get_sample_value("sample4"), 4.0);

	EXPECT_EQ(t.last_total_samples(), 4);
	EXPECT_EQ(t.raw_stats().scraped, 2);
	EXPECT_EQ(t.calc_stats().scraped, 2);
}

//TODO - Add tests involving infra_state
//TODO - Add tests to test the to_protobuf
