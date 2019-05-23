
#include <analyzer.h>
#include <run.h>
#include <sinsp_mock.h>
#include <gtest.h>
#include "container_analyzer.h"
#include "connectinfo.h"

using namespace test_helpers;

TEST(analyzer_test, end_to_end_basic)
{
	sinsp_mock inspector;
	// Make some fake events
	uint64_t ts = 1095379199000000000ULL;
	inspector.build_event().tid(55).ts(ts).count(5).commit();
	inspector.build_event().tid(55).ts(ts).count(1000).commit();
	inspector.build_event().tid(75).count(1).commit();

	sinsp_analyzer analyzer(&inspector, "/" /*root dir*/);
	run_sinsp_with_analyzer(inspector, analyzer);

	// TODO bryan NOW WHAT?!?!?
}

class test_helper
{
public:
	static unordered_map<std::string, analyzer_container_state>&
	get_analyzer_containers(sinsp_analyzer& analyzer)
	{
		return analyzer.m_containers;
	}

	static unordered_map<std::string, sinsp_container_info>&
	get_inspector_containers(sinsp& inspector)
	{
		return inspector.m_container_manager.m_containers;
	}

	static void coalesce(sinsp_analyzer& analyzer, vector<std::string>& emitted)
	{
		analyzer.coalesce_unemitted_stats(emitted);
	}

	static draiosproto::metrics* get_metrics(sinsp_analyzer& analyzer)
	{
		return analyzer.m_metrics;
	}

	static void set_proc_count(sinsp_analyzer& analyzer,
				   std::string name,
				   uint64_t count)
	{
		analyzer.m_containers[name].m_metrics.m_proc_count = count;
	}

	static void set_proc_start_count(sinsp_analyzer& analyzer,
				   std::string name,
				   uint64_t count)
	{
		analyzer.m_containers[name].m_metrics.m_proc_start_count = count;
	}

};

class container_stuff
{
public:
	container_stuff(sinsp& inspector,
			sinsp_analyzer& analyzer,
			std::string name)
		: m_name(name)
	{
		// stuff stuff in the right container maps for the analyzer and
		// inspector
		test_helper::get_analyzer_containers(analyzer)[m_name];
		test_helper::get_inspector_containers(inspector)[m_name];
		test_helper::get_inspector_containers(inspector)[m_name].m_id = m_name;
	}

	std::string m_name;
};

// for SMAGENT-1599, ensure we work if the container info is null
TEST(analyzer_test, coalesce_containers_null)
{
	sinsp_mock inspector;
	sinsp_analyzer analyzer(&inspector, "/");
	vector<std::string> emitted_containers;
	container_stuff unemitted_container_1(inspector, analyzer, "unemitted_container_1");
	container_stuff unemitted_container_2(inspector, analyzer, "unemitted_container_2");

	// remove container from container manager to simulate it getting deleted
	test_helper::get_inspector_containers(inspector).erase(unemitted_container_2.m_name);

	// coalesce. should crash if broken
	test_helper::coalesce(analyzer, emitted_containers);
	EXPECT_EQ(1, test_helper::get_metrics(analyzer)->unreported_counters().names().size());
}

TEST(analyzer_test, coalesce_containers_test)
{
	sinsp_mock inspector;
	sinsp_analyzer analyzer(&inspector, "/");

	vector<std::string> emitted_containers;

	// create 3 containers. we'll "emit" one of them and coalesce the other two
	container_stuff emitted_container(inspector, analyzer, "emitted_container");
	emitted_containers.push_back(emitted_container.m_name);
	container_stuff unemitted_container_1(inspector, analyzer, "unemitted_container_1");
	container_stuff unemitted_container_2(inspector, analyzer, "unemitted_container_2");

	// connection_queue_usage_pct
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_connection_queue_usage_pct = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_connection_queue_usage_pct = 2;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_connection_queue_usage_pct = 1;

	// fd_usage_pct
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_fd_usage_pct = 6;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_fd_usage_pct = 3;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_fd_usage_pct = 2;

	// cpu_pct
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_cpuload = 7;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_cpuload = 4;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_cpuload = 3;

	// resident_memory_usage_kb
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_res_memory_used_kb = 8;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_res_memory_used_kb = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_res_memory_used_kb = 4;

	// swap_memory_usage-kb
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_swap_memory_used_kb = 9;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_swap_memory_used_kb = 6;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_swap_memory_used_kb = 5;

	// major_pagefaults
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_pfmajor = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_pfmajor = 7;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_pfmajor = 6;

	// minor_pagefaults
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_pfminor = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_pfminor = 8;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_pfminor = 7;

	// fd_count
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_fd_count = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_fd_count = 9;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_fd_count = 8;

	// cpu_shares
	test_helper::get_inspector_containers(inspector)[emitted_container.m_name].m_cpu_shares = 5;
	test_helper::get_inspector_containers(inspector)[unemitted_container_1.m_name].m_cpu_shares = 10;
	test_helper::get_inspector_containers(inspector)[unemitted_container_2.m_name].m_cpu_shares = 9;

	// memory_limit_kb
	test_helper::get_inspector_containers(inspector)[emitted_container.m_name].m_memory_limit = 5 * 1024;
	test_helper::get_inspector_containers(inspector)[unemitted_container_1.m_name].m_memory_limit = 11 * 1024;
	test_helper::get_inspector_containers(inspector)[unemitted_container_2.m_name].m_memory_limit = 10 * 1024;

	// swap_limit_kb
	test_helper::get_inspector_containers(inspector)[emitted_container.m_name].m_swap_limit = 5 * 1024;
	test_helper::get_inspector_containers(inspector)[unemitted_container_1.m_name].m_swap_limit = 12 * 1024;
	test_helper::get_inspector_containers(inspector)[unemitted_container_2.m_name].m_swap_limit = 11 * 1024;

	// count_processes
	test_helper::set_proc_count(analyzer, emitted_container.m_name, 5);
	test_helper::set_proc_count(analyzer, unemitted_container_1.m_name, 13);
	test_helper::set_proc_count(analyzer, unemitted_container_2.m_name, 14);

	// proc_start_count
	test_helper::set_proc_start_count(analyzer, emitted_container.m_name, 5);
	test_helper::set_proc_start_count(analyzer, unemitted_container_1.m_name, 15);
	test_helper::set_proc_start_count(analyzer, unemitted_container_2.m_name, 14);

	// threads_count
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_threads_count = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_threads_count = 16;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_threads_count = 15;

	// coalesce
	test_helper::coalesce(analyzer, emitted_containers);

	// check that stats are correct in protobuf
	EXPECT_EQ(2, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().connection_queue_usage_pct());
	EXPECT_EQ(5, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().fd_usage_pct());
	EXPECT_EQ(700, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().cpu_pct());
	EXPECT_EQ(9, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().resident_memory_usage_kb());
	EXPECT_EQ(11, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().swap_memory_usage_kb());
	EXPECT_EQ(13, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().major_pagefaults());
	EXPECT_EQ(15, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().minor_pagefaults());
	EXPECT_EQ(17, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().fd_count());
	EXPECT_EQ(19, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().cpu_shares());
	EXPECT_EQ(21, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().memory_limit_kb());
	EXPECT_EQ(23, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().swap_limit_kb());
	EXPECT_EQ(27, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().count_processes());
	EXPECT_EQ(29, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().proc_start_count());
	EXPECT_EQ(31, test_helper::get_metrics(analyzer)->unreported_counters().resource_counters().threads_count());

	// check that we added the names
	EXPECT_EQ(2, test_helper::get_metrics(analyzer)->unreported_counters().names().size());

	// check that we cleared the containers
	EXPECT_EQ(test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_connection_queue_usage_pct, 0);
}
