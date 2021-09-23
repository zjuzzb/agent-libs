
#include <memory>
#include <string>
#include <vector>
#include <map>

#include "prom_base.h"
#include "prom_v1.h"
#include "promscrape_conf.h"
#include "prom_helper.h"
#include "prom_scrape_helper.h"
#include "prom_factory_helper.h"

#include <gtest.h>

using namespace prom_scrape_helper;

namespace
{
typedef std::map<std::string, std::string> label_map_t;
uint32_t DEFAULT_CACHE_SIZE = 10000;

const std::string url = "http://10.20.30.40:105";

prom_v1::tag_umap_t itags = { { "itag1", "ivalue1" } };
prom_job::tag_map_t tags = { { "tag1", "value1" } };
const int pid = 1024;
const std::string container_id = "ctr";
}

class prom_v1_helper
{
public:
	prom_v1_helper(std::shared_ptr<prom_base> s) : scraper(s)
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

	void send_config(const std::vector<prom_process> &prom_procs)
	{
		std::shared_ptr<prom_v1> p = std::dynamic_pointer_cast<prom_v1>(scraper);
		p->sendconfig_th(prom_procs);
	}

	int64_t find_job_id(int pid)
	{
		auto job_list = scraper->m_pids[pid];
		auto it = job_list.begin();
		if (it == job_list.end())
		{
			return 0;
		}
		return *it;
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

	std::shared_ptr<agent_promscrape::Config> get_last_config()
	{
		std::shared_ptr<prom_v1> p = std::dynamic_pointer_cast<prom_v1>(scraper);
		return p->m_config;
	}

	void set_last_config_ts(uint64_t ts)
	{
		std::shared_ptr<prom_v1> p = std::dynamic_pointer_cast<prom_v1>(scraper);
		p->m_last_config_ts = ts;
	}

private:
	std::shared_ptr<prom_base> scraper;
};

// Tests if a Job is created successfully if a URL is provided.
TEST(prom_v1_test, send_config_with_url)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_cert_path", "/dummy" }, { "auth_key_path", "/dummy/key" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	prom_job job = t.find_job(job_id);

	//Verify Job info
	EXPECT_EQ(job.url(), url);
	EXPECT_EQ(job.pid(), pid);
	EXPECT_EQ(job.container_id(), "ctr");
	ASSERT_TRUE(job.add_tags() == tags);
	EXPECT_EQ(job.stale(), false);

	auto cg = t.get_last_config();

	//Verify Config Info
	agent_promscrape::Target target;
	for (const auto &scrape_config : cg->scrape_configs())
	{
		if (scrape_config.job_id() == job_id)
		{
			target = scrape_config.target();
			break;
		}
	}

	// Target endpoint
	EXPECT_EQ(target.scheme(), "http");
	EXPECT_EQ(target.address(), "10.20.30.40:105");
	EXPECT_EQ(target.metrics_path(), "");
	EXPECT_EQ(target.tags(0).name(), "port");
	EXPECT_EQ(target.tags(0).value(), "105");
	EXPECT_EQ(target.tags(1).name(), "itag1");
	EXPECT_EQ(target.tags(1).value(), "ivalue1");
	EXPECT_EQ(target.auth_creds().auth_cert().auth_cert_path(), "/dummy");
	EXPECT_EQ(target.auth_creds().auth_cert().auth_key_path(), "/dummy/key");
}

//Tests if a job is created successfully if only a port is provided.
TEST(prom_v1_test, send_config_with_port)
{
	std::map<std::string, std::string> options = { { "username", "user1" }, { "password", "pwd" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	prom_job job = t.find_job(job_id);

	//Verify Job info
	EXPECT_EQ(job.url(), "http://localhost:5000/tmp/metrics");
	EXPECT_EQ(job.pid(), pid);
	EXPECT_EQ(job.container_id(), "ctr");
	ASSERT_TRUE(job.add_tags() == tags);
	EXPECT_EQ(job.stale(), false);

	auto cg = t.get_last_config();

	//Verify Config Info
	agent_promscrape::Target target;
	for (const auto &scrape_config : cg->scrape_configs())
	{
		if (scrape_config.job_id() == job_id)
		{
			target = scrape_config.target();
			break;
		}
	}

	// Target endpoint
	EXPECT_EQ(target.scheme(), "http");
	EXPECT_EQ(target.address(), "localhost:5000");
	EXPECT_EQ(target.metrics_path(), "/tmp/metrics");
	EXPECT_EQ(target.tags(0).name(), "port");
	EXPECT_EQ(target.tags(0).value(), "5000");
	EXPECT_EQ(target.auth_creds().auth_user_passwd().username(), "user1");
	EXPECT_EQ(target.auth_creds().auth_user_passwd().password(), "pwd");
}

//Tests if scrape result is ignored if a corresponding job id is not present.
TEST(prom_v1_test, handle_result_wrong_job_id)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_cert_path", "/dummy" }, { "auth_key_path", "/dummy/key" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);

	scrape.add_result(101, 202, url);
	build_sample_scrape(scrape, url, "");
	prom_helper::set_label_value(res.mutable_source_labels(), "sysdig_omit_source", "true");

	t.handle_result(res);
	prom_job job = t.find_job(job_id);

	//Verify omit source is not updated.
	EXPECT_EQ(job.omit_source(), false);
}

//Tests a successful processign of scrape result.
TEST(prom_v1_test, handle_result)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_cert_path", "/dummy" }, { "auth_key_path", "/dummy/key" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);

	scrape.add_result(job_id, 202, url);
	build_sample_scrape(scrape, url, "");

	t.handle_result(res);
	prom_job job = t.find_job(job_id);

	//Verify Job is created
	EXPECT_EQ(job.url(), url);
}

//Test if a job is update correctly after a successful scrape processing.
TEST(prom_v1_test, hand_result_update)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_cert_path", "/dummy" }, { "auth_key_path", "/dummy/key" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);

	scrape.add_result(job_id, 202, url);
	build_sample_scrape(scrape, url, "");

	t.handle_result(res);
	prom_job job = t.find_job(job_id);

	//Verify Job is created
	EXPECT_EQ(job.url(), url);
	EXPECT_EQ(job.omit_source(), false);

	agent_promscrape::ScrapeResult res2;
	scrape_maker scrape2(&res2);

	scrape2.add_result(job_id, 302, url);
	build_sample_scrape(scrape2, url, "");
	prom_helper::set_label_value(res2.mutable_source_labels(), "sysdig_omit_source", "true");

	t.handle_result(res2);
	prom_job job2 = t.find_job(job_id);

	//Verify Job is created
	EXPECT_EQ(job2.url(), url);
	EXPECT_EQ(job2.omit_source(), true);
}

//Tests if bypass logic works as expected.
TEST(prom_v1_test, hand_result_bypass)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_cert_path", "/dummy" }, { "auth_key_path", "/dummy/key" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	agent_promscrape::ScrapeResult res;
	scrape_maker scrape(&res);

	scrape.add_result(job_id, 202, url);
	build_sample_scrape(scrape, url, "");
	prom_helper::set_label_value(res.mutable_source_labels(), "sysdig_bypass", "true");

	scraper->set_allow_bypass(true);
	auto bypass_cb = [this](std::shared_ptr<draiosproto::raw_prometheus_metrics> msg) {};
	scraper->set_raw_bypass_callback(bypass_cb);

	t.handle_result(res);
	prom_job job = t.find_job(job_id);

	//Verify Job is created
	EXPECT_EQ(job.url(), url);
	EXPECT_EQ(job.bypass_limits(), true);

	//TODO - test the bypass protobuf
}

//Tests if jobs are marked stale correctly.
TEST(prom_v1_test, prune_jobs)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_cert_path", "/dummy" }, { "auth_key_path", "/dummy/key" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);
	conf.set_metric_expiration(1);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	t.set_last_config_ts(100);

	//5 seconds
	t.prune_jobs(5);

	EXPECT_EQ(t.find_job(job_id).stale(), true);
}

//Tests if a job gets deleted successfully from all stores.
TEST(prom_v1_test, delete_job)
{
	std::map<std::string, std::string> options = { { "url", url }, { "auth_token_path", "/dummy/token" } };
	prom_process p1("process1", pid, 1008, container_id, { 5000 }, "/tmp/metrics", options, tags, std::move(itags));
	std::vector<prom_process> prom_procs{p1};

	promscrape_conf conf;
	conf.set_prom_sd(false);
	conf.set_ingest_raw(true);
	conf.set_metric_expiration(1);

	filter_vec_t filters({ { "test.*", true } });
	metric_limits::sptr_t ml = std::make_shared<metric_limits>(std::move(filters), DEFAULT_CACHE_SIZE);

	auto cb = []() -> int {return 10;};
	std::shared_ptr<prom_base> scraper = prom_factory_helper::get(ml, conf, true, cb);
	prom_v1_helper t(scraper);

	t.send_config(prom_procs);

	int job_id = t.find_job_id(pid);
	EXPECT_NE(job_id, 0);

	t.delete_job(job_id);

	EXPECT_EQ(t.find_job_id(pid), 0);
	EXPECT_EQ(t.find_job(job_id).url(), "");
}

//TODO - Add tests involving infra_state
//TODO - Add tests to test the to_protobuf
