#include <memory>
#include <string>
#include <vector>
#include <map>

#include "prom_base.h"
#include "prom_v2.h"
#include "promscrape_conf.h"
#include "prom_helper.h"
#include "prom_scrape_helper.h"
#include "prom_factory_helper.h"

#include <gtest.h>

using namespace prom_scrape_helper;

#define ONE_SECOND_IN_NS 1000000000LL

namespace
{
uint32_t DEFAULT_CACHE_SIZE = 10000;
}

class prom_v2_helper
{
public:
	prom_v2_helper(std::shared_ptr<prom_base> s) : scraper(s)
	{
	}

	void handle_result(agent_promscrape::ScrapeResult &result)
	{
		scraper->handle_result(result);
	}

	void prune_jobs(uint64_t ts)
	{
		scraper->prune_jobs(ts);
	}

	void delete_job(int64_t job_id)
	{
		scraper->delete_job(job_id);
	}

	int64_t find_job_id(const std::string &url, const std::string &job_name)
	{
		auto key = make_pair(url, job_name);
		std::shared_ptr<prom_v2> p = std::dynamic_pointer_cast<prom_v2>(scraper);
		auto url_it = p->m_joburls.find(key);
		if (url_it != p->m_joburls.end())
		{
			return url_it->second;
		}
		return 0;
	}

	prom_job find_job(int64_t job_id)
	{
		auto it = scraper->m_jobs.find(job_id);
		if (it != scraper->m_jobs.end())
		{
			return it->second;
		}
		return prom_job("");
	}

private:
	std::shared_ptr<prom_base> scraper;
};

//Test if a new job is not created for a new scrape
//result with no url
TEST(prom_v2_test, handle_result_with_no_url)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);
	const std::string url = "";
	const std::string job_name = "job1";

	scrape.add_result(101, 202, url);
	build_sample_scrape(scrape, url, job_name);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	promscrape_conf conf;
	conf.set_prom_sd(true);

	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v2_helper t(scraper);

	t.handle_result(res);

	EXPECT_EQ(t.find_job_id(url, job_name), 0);
}

//Test if a new job is created successfully for a new scrape
//result.
TEST(prom_v2_test, handle_result)
{
	//Job1
	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);
	const std::string url = "100.10.20.30:105";
	const std::string job_name = "job1";

	scrape.add_result(101, 202, url);
	build_sample_scrape(scrape, url, job_name);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	promscrape_conf conf;
	conf.set_prom_sd(true);

	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v2_helper t(scraper);

	t.handle_result(res);

	EXPECT_EQ(t.find_job_id(url, job_name), 1);
	EXPECT_EQ(t.find_job(1).url(), url);

	//Job2
	agent_promscrape::ScrapeResult res2;
	scrape_maker scrape2(&res2);

	const std::string url2 = "100.10.20.30:106";
	const std::string job2_name = "job2";

	scrape2.add_result(102, 300, url2);
	build_sample_scrape(scrape2, url2, job2_name);

	t.handle_result(res2);

	EXPECT_EQ(t.find_job_id(url2, job2_name), 2);
	EXPECT_EQ(t.find_job(2).url(), url2);
}

//Test if an existing job is updated successfully for a new scrape
//result.
TEST(prom_v2_test, handle_result_update)
{
	//Job1
	agent_promscrape::ScrapeResult res1;
	scrape_maker scrape1(&res1);
	const std::string url = "100.10.20.30:105";
	const std::string job_name = "job1";

	scrape1.add_result(101, 200, url);
	build_sample_scrape(scrape1, url, job_name);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	promscrape_conf conf;
	conf.set_prom_sd(true);

	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v2_helper t(scraper);

	t.handle_result(res1);

	//Note that 3 is because prev test created 2 jobs.
	EXPECT_EQ(t.find_job_id(url, job_name), 3);
	EXPECT_EQ(t.find_job(3).url(), url);
	EXPECT_EQ(t.find_job(3).omit_source(), false);

	//Job1 with updated timestamp
	agent_promscrape::ScrapeResult res2;
	scrape_maker scrape2(&res2);

	scrape2.add_result(101, 300, url);
	build_sample_scrape(scrape2, url, job_name);
	prom_helper::set_label_value(res2.mutable_source_labels(), "sysdig_omit_source", "true");

	t.handle_result(res2);

	EXPECT_EQ(t.find_job_id(url, job_name), 3);
	EXPECT_EQ(t.find_job(3).url(), url);
	EXPECT_EQ(t.find_job(3).omit_source(), true);
}

//Test a new job with allow_bypass returns successfully.
//TODO - test the returned bypass protobuf
TEST(prom_v2_test, handle_result_allow_bypass)
{
	//Job1
	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);
	const std::string url = "100.10.20.30:105";
	const std::string job_name = "job1";

	scrape.add_result(101, 200, url);
	build_sample_scrape(scrape, url, job_name);
	prom_helper::set_label_value(res.mutable_source_labels(), "sysdig_bypass", "true");

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	promscrape_conf conf;
	conf.set_prom_sd(true);

	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	scraper->set_allow_bypass(true);
	auto bypass_cb = [this](std::shared_ptr<draiosproto::raw_prometheus_metrics> msg) {};
	scraper->set_raw_bypass_callback(bypass_cb);

	prom_v2_helper t(scraper);
	t.handle_result(res);

	EXPECT_EQ(t.find_job_id(url, job_name), 4);
	EXPECT_EQ(t.find_job(4).url(), url);
	EXPECT_EQ(t.find_job(4).stale(), false);

	//TODO test the returned protobuf
}

//Test if a job is correctly marked stale.
TEST(prom_v2_test, prune_jobs)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);
	const std::string url = "100.10.20.30:105";
	const std::string job_name = "job1";

	scrape.add_result(101, 200, url);
	build_sample_scrape(scrape, url, job_name);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	promscrape_conf conf;
	conf.set_prom_sd(true);
	//1 seconds
	conf.set_metric_expiration(1);

	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);

	prom_v2_helper t(scraper);
	t.handle_result(res);

	//5 seconds
	t.prune_jobs(5 * ONE_SECOND_IN_NS);

	EXPECT_EQ(t.find_job_id(url, job_name), 5);
	EXPECT_EQ(t.find_job(5).stale(), true);

}

//Test if a job is deleted correctly
TEST(prom_v2_test, delete_job)
{
	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);
	const std::string url = "100.10.20.30:105";
	const std::string job_name = "job1";

	scrape.add_result(101, 200, url);
	build_sample_scrape(scrape, url, job_name);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	promscrape_conf conf;
	conf.set_prom_sd(true);

	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);

	prom_v2_helper t(scraper);
	t.handle_result(res);

	EXPECT_EQ(t.find_job_id(url, job_name), 6);

	t.delete_job(6);

	EXPECT_EQ(t.find_job_id(url, job_name), 0);
	EXPECT_EQ(t.find_job(6).url(), "");
}

//TODO - Add tests involving infra_state
//TODO - Add tests to test the to_protobuf
