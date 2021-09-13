#include "prom_metadata_scraper.h"
#include <gtest.h>
#include <string>
#include <memory>

class test_helper
{
public:
	test_helper(prom_metadata_scraper *s) : scraper(s)
	{
	}
	void process_metadata(const Json::Value &data)
	{
		scraper->process_metadata(data);
	}
	void process_targets(const Json::Value &data)
	{
		scraper->process_targets(data);
	}

	std::map<std::string, prom_metadata_scraper::target_data> get_target_data() { return scraper->m_target_map; }
	std::map<std::string, prom_job_metadata> get_metadata() { return scraper->m_metadata_map; }

	bool find_metadata_instance(const std::string &instance)
	{
		return scraper->m_metadata_map.find(instance) != scraper->m_metadata_map.end();
	}

	bool find_target(const std::string &instance)
	{
		return scraper->m_target_map.find(instance) != scraper->m_target_map.end();
	}
private:
	prom_metadata_scraper *scraper;
};

//Test if no collection happens if stats are not enabled
TEST(prom_metadata_scraper_test, periodic_gather_stats)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	scraper.periodic_gather_stats();
	ASSERT_TRUE(t.get_metadata().empty());
	ASSERT_TRUE(t.get_target_data().empty());
}

//Test if no collection happens if stats are not enabled
TEST(prom_metadata_scraper_test, gather_target_stats)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	scraper.gather_target_stats();
	ASSERT_TRUE(t.get_metadata().empty());
	ASSERT_TRUE(t.get_target_data().empty());
}

//Test if no data is present in the given input, exit
//gracefully.
TEST(prom_metadata_scraper_test, process_metadata_no_data)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	Json::Value data;

	t.process_metadata(data);

	ASSERT_TRUE(t.get_metadata().empty());

}

//Test if data doesn't have an instance name in the given input,
//exit gracefully
TEST(prom_metadata_scraper_test, process_metadata_no_instance)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	std::string metadata = R"EOF(
		{ 
		"data": [ 
			{ 
				"target": { 
				"instance": "", 
				"job": "k8s-pods", 
				"sysdig_k8s_pod_container_name": "dnsmasq", 
				"sysdig_k8s_pod_uid": "a7f461bd-78da-4c48-8cbf-671edcf014df" 
				}, 
				"metric": "process_open_fds", 
				"type": "gauge", 
				"help": "Number of open file descriptors.", 
				"unit": "" 
			}
		]
		}
        )EOF";

	Json::Value data;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(metadata, data));

	t.process_metadata(data);
	ASSERT_TRUE(t.get_metadata().empty());
}

//Test a successful metadata process
TEST(prom_metadata_scraper_test, process_metadata)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	std::string metadata = R"EOF(
		{ 
		"data": [ 
			{ 
				"target": { 
					"instance": "100.101.83.1:100", 
					"job": "k8s-pods", 
					"sysdig_k8s_pod_container_name": "dnsmasq", 
					"sysdig_k8s_pod_uid": "a7f461bd-78da-4c48-8cbf-671edcf014df" 
				}, 
				"metric": "process_open_fds", 
				"type": "gauge", 
				"help": "Number of open file descriptors.", 
				"unit": "" 
			},
		    {
				"target": {
					"instance": "100.105.83.1:200",
					"job": "k8s-pods",
					"sysdig_k8s_pod_container_name": "dnsmasq",
					"sysdig_k8s_pod_uid": "a7f461bd-78da-4c48-8cbf-671edcf014df"
				},
				"metric": "process_start_time_seconds",
				"type": "gauge",
				"help": "Start time of the process since unix epoch in seconds.",
				"unit": ""
			}
		]
		}
        )EOF";

	Json::Value data;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(metadata, data));

	t.process_metadata(data);
	ASSERT_TRUE(t.find_metadata_instance("100.101.83.1:100"));
	ASSERT_TRUE(t.find_metadata_instance("100.105.83.1:200"));
	EXPECT_EQ(t.get_metadata().size(), 2);

}

//Test if no data is provided, exit gracefully
TEST(prom_metadata_scraper_test, process_targets_no_data)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	Json::Value targets;

	t.process_targets(targets);
	ASSERT_TRUE(t.get_target_data().empty());
}

//Test if no scrape url is provided, exit gracefully
TEST(prom_metadata_scraper_test, process_targets_no_scrape_url)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	std::string targets = R"EOF(
		{
		"data": { 
			"activeTargets": [
			{
				"discoveredLabels": {
				  "__meta_kubernetes_pod_name": "kube-dns-684d554478-f87zn"
				},
				"scrapePool": "k8s-pods",
				"lastError": "",
				"health": "up"
			}
			]
		}
		}
        )EOF";
	Json::Value data;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(targets, data));

	t.process_targets(data);
	ASSERT_TRUE(t.get_target_data().empty());
}

//Test if no health information is available, exit gracefully
TEST(prom_metadata_scraper_test, process_targets_no_health)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	std::string targets = R"EOF(
		{
		"data": {  
			"activeTargets": [
			{
				"discoveredLabels": {
				  "__meta_kubernetes_pod_name": "kube-dns-684d554478-f87zn"
				},
				"scrapePool": "k8s-pods",
				"scrapeUrl": "http://100.105.83.3:10055/metrics",
				"lastError": ""
			}
			]
		}
		}
        )EOF";
	Json::Value data;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(targets, data));

	t.process_targets(data);
	ASSERT_TRUE(t.get_target_data().empty());
}

//Test processing targets are done correctly.
TEST(prom_metadata_scraper_test, process_targets)
{
	prom_metadata_scraper scraper;
	test_helper t(&scraper);
	std::string targets = R"EOF(
		{
		"data": {  
			"activeTargets": [
			{
				"discoveredLabels": {
				  "__meta_kubernetes_pod_name": "kube-dns-684d554478-f87zn"
				},
				"scrapePool": "k8s-pods",
				"scrapeUrl": "http://100.105.83.3:10055/metrics",
				"lastError": "",
				"health": "up"
			}
			]
		}
		}
        )EOF";
	Json::Value data;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse(targets, data));

	t.process_targets(data);
	ASSERT_TRUE(t.find_target("http://100.105.83.3:10055/metrics"));
}

