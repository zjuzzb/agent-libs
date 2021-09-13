#include "prom_job_metadata.h"
#include <gtest.h>
#include <string>
#include <memory>

namespace
{
const std::string URL = "100.105.83.1:10055";

void set_sample_result(const std::shared_ptr<agent_promscrape::ScrapeResult> &res,
					   const std::string &sname)
{
	auto sample = res->add_samples();
	sample->set_metric_name(sname);
	sample->set_value(1.0);
}
}

//No name metric
TEST(prom_job_metadata_test, process_empty_metric_metadata)
{
	std::string target = R"EOF(
        {
        "target": {
            "instance": "100.105.83.1:10055",
            "job": "k8s-pods",
            "sysdig_k8s_pod_container_name": "dnsmasq",
            "sysdig_k8s_pod_uid": "a7f461bd-78da-4c48-8cbf-671edcf014df"
        },
        "metric": "",
        "type": "gauge",
        "help": "Number of open file descriptors.",
        "unit": ""
        }
        )EOF";

	Json::Value metric;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(target, metric));

	prom_job_metadata pjm(URL);
	pjm.process_metric_metadata(metric);
	ASSERT_TRUE(pjm.get_metadata().empty());
}

//Process a metric successfully
TEST(prom_job_metadata_test, process_metric_metadata)
{
	std::string target = R"EOF(
        {
        "target": {
            "instance": "100.105.83.1:10055",
            "job": "k8s-pods",
            "sysdig_k8s_pod_container_name": "dnsmasq",
            "sysdig_k8s_pod_uid": "a7f461bd-78da-4c48-8cbf-671edcf014df"
        },
        "metric": "process_open_fds",
        "type": "gauge",
        "help": "Number of open file descriptors.",
        "unit": "ONE"
        }
        )EOF";

	Json::Value metric;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(target, metric));

	prom_job_metadata pjm(URL);
	pjm.process_metric_metadata(metric);
	std::map<std::string, metric_metadata_t> out_map = pjm.get_metadata();
	ASSERT_FALSE(out_map.empty());
	EXPECT_EQ(out_map.size(), 1);
	EXPECT_EQ(out_map["process_open_fds"].type, "gauge");
	EXPECT_EQ(out_map["process_open_fds"].help, "Number of open file descriptors.");
	EXPECT_EQ(out_map["process_open_fds"].unit, "ONE");
	EXPECT_EQ(out_map["process_open_fds"].timeseries, 0);
}

//An empty scrape should return unchanged prom_job_metadata
TEST(prom_job_metadata_test, process_empty_scrape)
{
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	prom_job_metadata pjm(URL);
	pjm.process_scrape(result_ptr);
	ASSERT_TRUE(pjm.get_metadata().empty());
}

//An empty prom_job_metadata_map should not process any scrape.
TEST(prom_job_metadata_test, process_scrape_with_empty_metadata)
{
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	result_ptr = std::make_shared<agent_promscrape::ScrapeResult>();
	prom_job_metadata pjm(URL);
	pjm.process_scrape(result_ptr);
	ASSERT_TRUE(pjm.get_metadata().empty());
}

//Process a scrape successfully.
TEST(prom_job_metadata_test, process_scrape)
{
	std::string target = R"EOF(
        {
        "target": {
            "instance": "100.105.83.1:10055",
            "job": "k8s-pods",
            "sysdig_k8s_pod_container_name": "dnsmasq",
            "sysdig_k8s_pod_uid": "a7f461bd-78da-4c48-8cbf-671edcf014df"
        },
        "metric": "process_open_fds",
        "type": "gauge",
        "help": "Number of open file descriptors.",
        "unit": "ONE"
        }
        )EOF";

	Json::Value metric;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(target, metric));

	prom_job_metadata pjm(URL);
	pjm.process_metric_metadata(metric);

	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	result_ptr = std::make_shared<agent_promscrape::ScrapeResult>();
	set_sample_result(result_ptr, "process_open_fds");
	set_sample_result(result_ptr, "process_open_fds_sum");
	set_sample_result(result_ptr, "process_open_fds_count");
	set_sample_result(result_ptr, "process_open_fds_bucket");

	pjm.process_scrape(result_ptr);
	EXPECT_EQ(pjm.get_metadata()["process_open_fds"].timeseries, 4);
}
