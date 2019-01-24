#include <gtest.h>
#include <sinsp_int.h>
#include "container_emitter.h"
#include <config.h>
#include <analyzer.h>
#include <connectinfo.h>
#include <proc_filter.h>

// test class that allows us to give information about the contaienrs required
// for emitting without forcing us to create the entire analyzer
static const uint32_t test_statsd_limit = 345;
static const uint32_t test_flush_flags = 4543;

class fake_analyzer_t
{
public:
	fake_analyzer_t()
		: m_configuration(&m_configuration_instance)
	{
		m_container_filter.reset(new proc_filter::conf("container_filter"));
		m_container_filter->set_enabled(true);

		proc_filter::filter_condition my_condition;
		my_condition.m_param_type = proc_filter::filter_condition::container_label;
		my_condition.m_param = "container.label.com.sysdig.report";
		my_condition.m_pattern = "true";

		proc_filter::filter_rule my_rule;
		my_rule.m_include = true;
		my_rule.m_cond.emplace_back(my_condition);

		proc_filter::filter_condition my_condition_2;
		my_condition_2.m_param_type = proc_filter::filter_condition::all;
		proc_filter::filter_rule my_rule_2;
		my_rule_2.m_include = true;
		my_rule_2.m_cond.emplace_back(my_condition_2);

		vector<proc_filter::filter_rule> my_rules;
		my_rules.emplace_back(my_rule);
		my_rules.emplace_back(my_rule_2);

		m_container_filter->set_rules(my_rules);
		m_configuration_instance.set_container_filter(m_container_filter);
	}

        shared_ptr<proc_filter::conf> m_container_filter;

	std::unordered_map<std::string, analyzer_container_state> containers;
	std::unordered_map<string, vector<sinsp_threadinfo*>> progtable;
	std::unordered_map<string, sinsp_container_info> sinsp_containers;

	// stuff necessary for template
	sinsp_container_info* get_container(const string& container_id)
	{
		return &sinsp_containers[container_id];
	}
	sinsp_configuration m_configuration_instance;
	sinsp_configuration* m_configuration;
	infrastructure_state* infra_state()
	{
		return NULL;
	}
	uint64_t m_prev_flush_time_ns;

	vector<string> emittable_containers;
	static void found_emittable_containers(fake_analyzer_t& fake_analyzer,
					       const vector<string>& containers,
					       const unordered_map<string, vector<sinsp_threadinfo*>> progtable)
	{
		fake_analyzer.emittable_containers.insert(fake_analyzer.emittable_containers.end(),
							  containers.begin(),
							  containers.end());
	}
	set<string> emitted_containers;
	void emit_container(const string &container_id,
				   unsigned *statsd_limit,
				   uint64_t total_cpu_shares,
				   sinsp_threadinfo* tinfo,
				   uint32_t flush_flags)
	{
		ASSERT_EQ(flush_flags, test_flush_flags);
		emitted_containers.insert(container_id);
	}



};

typedef container_emitter<fake_analyzer_t, uint32_t> test_container_emitter;

TEST(container_emitter, patterns)
{
	// double check that patterns still work. it's mostly deprecated...but check it anyway
	fake_analyzer_t fake_analyzer;

	fake_analyzer.containers["k8s container"];
	fake_analyzer.progtable["k8s container"] = {};
	fake_analyzer.sinsp_containers["k8s container"].m_is_pod_sandbox = true;

	fake_analyzer.containers["maybe container 1"].m_metrics.m_cpuload = 1000000;
	fake_analyzer.progtable["maybe container 1"] = {};
	fake_analyzer.sinsp_containers["maybe container 1"].m_image = "stop. zipper time.";

	fake_analyzer.containers["maybe container 2"].m_reported_count = 1123098;
	fake_analyzer.progtable["maybe container 2"] = {};
	fake_analyzer.sinsp_containers["maybe container 2"].m_name = "go go gadget zipper";

	vector<string> emitted_containers;

	vector<string> patterns;
	patterns.emplace_back("gadget");

	test_container_emitter emitter(fake_analyzer,
				       fake_analyzer.containers,
				       test_statsd_limit,
				       fake_analyzer.progtable,
				       patterns,
				       test_flush_flags,
				       1000000,
				       false,
				       emitted_containers);
	emitter.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 1);
	ASSERT_NE(fake_analyzer.emitted_containers.find("maybe container 2"), fake_analyzer.emitted_containers.end());
	ASSERT_EQ(fake_analyzer.emittable_containers.size(), 1);
	ASSERT_EQ(emitted_containers.size(), 1);
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"maybe container 2"), emitted_containers.end());
}

TEST(container_emitter, smart_filter_test)
{
	// We need to try the following functionality
	// -kubernetes pod threads are skipped
	// -containers are properly sorted into can/must report
	// -run with limit < must report container count
	// --verify oldest contaienrs reported first
	// --verify highest stats containers reported in group that gets spli
	// -run with limit between must_report counta and total count
	// -run with limit greater than the number of containers

	fake_analyzer_t fake_analyzer;

	fake_analyzer.containers["k8s container"];
	fake_analyzer.progtable["k8s container"] = {};
	fake_analyzer.sinsp_containers["k8s container"].m_is_pod_sandbox = true;

	fake_analyzer.containers["maybe container 1"].m_metrics.m_cpuload = 1000000;
	fake_analyzer.progtable["maybe container 1"] = {};
	fake_analyzer.sinsp_containers["maybe container 1"];

	fake_analyzer.containers["maybe container 2"].m_reported_count = 1123098;
	fake_analyzer.progtable["maybe container 2"] = {};
	fake_analyzer.sinsp_containers["maybe container 2"];

	fake_analyzer.containers["old container"].m_reported_count = 10000000;
	fake_analyzer.progtable["old container"] = {};
	fake_analyzer.sinsp_containers["old container"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["young container"].m_reported_count = 0;
	fake_analyzer.containers["young container"].m_metrics.m_cpuload = 100000;
	fake_analyzer.progtable["young container"] = {};
	fake_analyzer.sinsp_containers["young container"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["high net"].m_req_metrics.m_io_net.add_in(1, 100000, 1000000);
	fake_analyzer.containers["high net"].m_reported_count = 1;
	fake_analyzer.progtable["high net"] = {};
	fake_analyzer.sinsp_containers["high net"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["high cpu"].m_metrics.m_cpuload = 100000;
	fake_analyzer.containers["high cpu"].m_reported_count = 1;
	fake_analyzer.progtable["high cpu"] = {};
	fake_analyzer.sinsp_containers["high cpu"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["high file"].m_req_metrics.m_io_file.add_in(1, 100000, 1000000);
	fake_analyzer.containers["high file"].m_reported_count = 1;
	fake_analyzer.progtable["high file"] = {};
	fake_analyzer.sinsp_containers["high file"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["high mem"].m_metrics.m_res_memory_used_kb = 100000;
	fake_analyzer.containers["high mem"].m_reported_count = 1;
	fake_analyzer.progtable["high mem"] = {};
	fake_analyzer.sinsp_containers["high mem"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["low net"].m_reported_count = 1;
	fake_analyzer.progtable["low net"] = {};
	fake_analyzer.sinsp_containers["low net"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["low cpu"].m_reported_count = 1;
	fake_analyzer.progtable["low cpu"] = {};
	fake_analyzer.sinsp_containers["low cpu"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["low file"].m_reported_count = 1;
	fake_analyzer.progtable["low file"] = {};
	fake_analyzer.sinsp_containers["low file"].m_labels["container.label.com.sysdig.report"] = "true";

	fake_analyzer.containers["low mem"].m_reported_count = 1;
	fake_analyzer.progtable["low mem"] = {};
	fake_analyzer.sinsp_containers["low mem"].m_labels["container.label.com.sysdig.report"] = "true";

	// absolute ordering should be:
	// old
	// high net/cpu/file/mem
	// low net/cpu/file/mem
	// young container
	// maybe container 1/2


	// First subtest: higher limit than container count
	vector<string> emitted_containers;

	vector<string> patterns;
	test_container_emitter emitter(fake_analyzer,
				       fake_analyzer.containers,
				       test_statsd_limit,
				       fake_analyzer.progtable,
				       patterns,
				       test_flush_flags,
				       1000000,
				       false,
				       emitted_containers);
	emitter.emit_containers();

	// validate the following all contain the correct containers
	// 1) list of containers which we determined were emittable
	// 2) list of containers which we actually emitted
	// 3) returned list of containers which we claimed to emit
	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 12);
	ASSERT_EQ(fake_analyzer.emitted_containers.find("k8s container"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("maybe container 1"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("maybe container 2"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("old container"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("young container"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high net"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high cpu"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high file"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high mem"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low mem"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low file"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low net"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low cpu"), fake_analyzer.emitted_containers.end());

	ASSERT_EQ(fake_analyzer.emittable_containers.size(), 12);
	ASSERT_EQ(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"k8s container"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"maybe container 1"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"maybe container 2"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"old container"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"young container"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"high net"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"high cpu"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"high file"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"high mem"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"low mem"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"low file"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"low net"), fake_analyzer.emittable_containers.end());
	ASSERT_NE(std::find(fake_analyzer.emittable_containers.begin(), fake_analyzer.emittable_containers.end(),"low cpu"), fake_analyzer.emittable_containers.end());

	ASSERT_EQ(emitted_containers.size(), 12);
	ASSERT_EQ(std::find(emitted_containers.begin(), emitted_containers.end(),"k8s container"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"maybe container 1"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"maybe container 2"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"old container"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"young container"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high net"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high cpu"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high file"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high mem"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low mem"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low file"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low net"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low cpu"), emitted_containers.end());

	// check that we incremented the ages
	ASSERT_EQ(fake_analyzer.containers["young container"].m_reported_count, 1);

	// second subtest: only marked containers get sent
	emitted_containers.clear();
	fake_analyzer.emittable_containers.clear();
	fake_analyzer.emitted_containers.clear();

	test_container_emitter emitter2(fake_analyzer,
					fake_analyzer.containers,
					test_statsd_limit,
					fake_analyzer.progtable,
					patterns,
					test_flush_flags,
					10,
					false,
					emitted_containers);
	emitter2.emit_containers();

	//ASSERT_EQ(fake_analyzer.emitted_containers.size(), 10);
	ASSERT_NE(fake_analyzer.emitted_containers.find("old container"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("young container"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high net"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high cpu"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high file"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high mem"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low mem"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low file"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low net"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("low cpu"), fake_analyzer.emitted_containers.end());

	ASSERT_EQ(fake_analyzer.emittable_containers.size(), 12);

	ASSERT_EQ(emitted_containers.size(), 10);
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"old container"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"young container"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high net"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high cpu"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high file"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high mem"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low mem"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low file"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low net"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"low cpu"), emitted_containers.end());

	ASSERT_EQ(fake_analyzer.containers["young container"].m_reported_count, 2);

	// third subtest: when splitting on age, high stat containers get sent
	emitted_containers.clear();
	fake_analyzer.emittable_containers.clear();
	fake_analyzer.emitted_containers.clear();

	test_container_emitter emitter3(fake_analyzer,
					fake_analyzer.containers,
					test_statsd_limit,
					fake_analyzer.progtable,
					patterns,
					test_flush_flags,
					5,
					false,
					emitted_containers);
	emitter3.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 5);
	ASSERT_NE(fake_analyzer.emitted_containers.find("old container"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high net"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high cpu"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high file"), fake_analyzer.emitted_containers.end());
	ASSERT_NE(fake_analyzer.emitted_containers.find("high mem"), fake_analyzer.emitted_containers.end());

	ASSERT_EQ(fake_analyzer.emittable_containers.size(), 12);

	ASSERT_EQ(emitted_containers.size(), 5);
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"old container"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high net"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high cpu"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high file"), emitted_containers.end());
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"high mem"), emitted_containers.end());

	// negative test...ensure we don't increment stuff we don't emit
	ASSERT_EQ(fake_analyzer.containers["young container"].m_reported_count, 2);

	// fourth subtest: double check age split, and only have 1 container
	emitted_containers.clear();
	fake_analyzer.emittable_containers.clear();
	fake_analyzer.emitted_containers.clear();

	test_container_emitter emitter4(fake_analyzer,
					fake_analyzer.containers,
					test_statsd_limit,
					fake_analyzer.progtable,
					patterns,
					test_flush_flags,
					1,
					false,
					emitted_containers);
	emitter4.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 1);
	ASSERT_NE(fake_analyzer.emitted_containers.find("old container"), fake_analyzer.emitted_containers.end());

	ASSERT_EQ(fake_analyzer.emittable_containers.size(), 12);

	ASSERT_EQ(emitted_containers.size(), 1);
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"old container"), emitted_containers.end());

	ASSERT_EQ(fake_analyzer.containers["young container"].m_reported_count, 2);

	// fifth subtest: have a non %4=0 count to ensure we split correctly
	emitted_containers.clear();
	fake_analyzer.emittable_containers.clear();
	fake_analyzer.emitted_containers.clear();

	test_container_emitter emitter5(fake_analyzer,
					fake_analyzer.containers,
					test_statsd_limit,
					fake_analyzer.progtable,
					patterns,
					test_flush_flags,
					3,
					false,
					emitted_containers);
	emitter5.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 1);
	ASSERT_NE(fake_analyzer.emitted_containers.find("old container"), fake_analyzer.emitted_containers.end());

	ASSERT_EQ(fake_analyzer.emittable_containers.size(), 12);

	ASSERT_EQ(emitted_containers.size(), 1);
	ASSERT_NE(std::find(emitted_containers.begin(), emitted_containers.end(),"old container"), emitted_containers.end());

	ASSERT_EQ(fake_analyzer.containers["young container"].m_reported_count, 2);
}


TEST(container_emitter, end_of_list_fencepost)
{
	// need to check that we correctly report all containers up to the end of the list.
	// so here we'll just spawn like 1 old container and 4 new ones and make sure we get
	// all 5
	fake_analyzer_t fake_analyzer;

	fake_analyzer.containers["old container"].m_reported_count = 1123098;
	fake_analyzer.progtable["old container"] = {};
	fake_analyzer.sinsp_containers["old container"].m_name = "old container";

	fake_analyzer.containers["new container"].m_reported_count = 0;
	fake_analyzer.progtable["new container"] = {};
	fake_analyzer.sinsp_containers["new container"];
	fake_analyzer.containers["new container2"].m_reported_count = 0;
	fake_analyzer.progtable["new container2"] = {};
	fake_analyzer.sinsp_containers["new container2"];
	fake_analyzer.containers["new container3"].m_reported_count = 0;
	fake_analyzer.progtable["new container3"] = {};
	fake_analyzer.sinsp_containers["new container3"];
	fake_analyzer.containers["new container4"].m_reported_count = 0;
	fake_analyzer.progtable["new container4"] = {};
	fake_analyzer.sinsp_containers["new container4"];

	vector<string> emitted_containers;
	vector<string> patterns;
	test_container_emitter emitter(fake_analyzer,
				       fake_analyzer.containers,
				       test_statsd_limit,
				       fake_analyzer.progtable,
				       patterns,
				       test_flush_flags,
				       5,
				       false,
				       emitted_containers);
	emitter.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 5);
}

TEST(container_emitter, next_age_empty)
{
	// check that we don't crash if the last age class aligns with the end
	// of the list. So just have 1 container and check that we don't crash
	fake_analyzer_t fake_analyzer;

	fake_analyzer.containers["old container"].m_reported_count = 1123098;
	fake_analyzer.progtable["old container"] = {};
	fake_analyzer.sinsp_containers["old container"].m_name = "old container";

	vector<string> emitted_containers;
	vector<string> patterns;
	test_container_emitter emitter(fake_analyzer,
				       fake_analyzer.containers,
				       test_statsd_limit,
				       fake_analyzer.progtable,
				       patterns,
				       test_flush_flags,
				       5,
				       false,
				       emitted_containers);
	emitter.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 1);
}

TEST(container_emitter, not_too_many_maybes)
{
	// check that if we don't have any high-priority containers, that we don't
	// report too many low-priority ones.
	fake_analyzer_t fake_analyzer;

	fake_analyzer.containers["old container"].m_reported_count = 0;
	fake_analyzer.progtable["old container"] = {};
	fake_analyzer.sinsp_containers["old container"];
	fake_analyzer.containers["new container"].m_reported_count = 1;
	fake_analyzer.progtable["new container"] = {};
	fake_analyzer.sinsp_containers["new container"];
	fake_analyzer.containers["new container2"].m_reported_count = 2;
	fake_analyzer.progtable["new container2"] = {};
	fake_analyzer.sinsp_containers["new container2"];
	fake_analyzer.containers["new container3"].m_reported_count = 3;
	fake_analyzer.progtable["new container3"] = {};
	fake_analyzer.sinsp_containers["new container3"];
	fake_analyzer.containers["new container4"].m_reported_count = 4;
	fake_analyzer.progtable["new container4"] = {};
	fake_analyzer.sinsp_containers["new container4"];

	vector<string> emitted_containers;
	vector<string> patterns;
	test_container_emitter emitter(fake_analyzer,
				       fake_analyzer.containers,
				       test_statsd_limit,
				       fake_analyzer.progtable,
				       patterns,
				       test_flush_flags,
				       3,
				       false,
				       emitted_containers);
	emitter.emit_containers();

	ASSERT_EQ(fake_analyzer.emitted_containers.size(), 3);
}
