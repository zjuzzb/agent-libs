#include "promscrape.h"
#include <gtest.h>

class test_helper
{
public:
	static void insert_scrape_result(promscrape *scrape, agent_promscrape::ScrapeResult &result)
	{
		scrape->handle_result(result);
	}
};

static void set_sample_result(agent_promscrape::ScrapeResult *res,
	int64_t job_id, int64_t timestamp, string sname, double value)
{
	res->set_job_id(job_id);
	res->set_timestamp(timestamp);
	auto sample = res->add_samples();
	sample->set_metric_name(sname);
	sample->set_value(value);
}

TEST(promscrape_test, enter_and_output_result)
{
	prometheus_conf conf;
	promscrape scrape(nullptr, conf, false, nullptr);
	agent_promscrape::ScrapeResult res1, res2;

	set_sample_result(&res1, 101, 202, "test", 123.0);
	test_helper::insert_scrape_result(&scrape, res1);

	set_sample_result(&res2, 1001, 2002, "hello", 3.14);
	test_helper::insert_scrape_result(&scrape, res2);

	draiosproto::app_info prom_info;
	unsigned int limit = 100, max_limit = 100, filtered = 0, total = 0;
	scrape.job_to_protobuf(101, &prom_info, limit, max_limit, &filtered, &total);

	// EXPECT_EQ(prom_info.metrics()[0].name(), "test");
	EXPECT_DOUBLE_EQ(prom_info.metrics()[0].value(), res1.samples()[0].value());
}
