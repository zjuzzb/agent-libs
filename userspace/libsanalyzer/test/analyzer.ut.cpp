
#include <analyzer.h>
#include <run.h>
#include <sinsp_mock.h>
#include <gtest.h>
#include "container_analyzer.h"
#include "connectinfo.h"
#include <scoped_config.h>
#include <scoped_sinsp_logger_capture.h>

using namespace test_helpers;

namespace {
sinsp_analyzer::flush_queue g_queue(1000);
audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_handler;
}

TEST(analyzer_test, end_to_end_basic)
{
	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock());

	auto &thread55 = inspector->build_thread().tid(55).commit();
	auto &thread75 = inspector->build_thread().tid(75).commit();

	// Make some fake events
	uint64_t ts = 1095379199000000000ULL;
	inspector->build_event(thread55).ts(ts).count(5).commit();
	inspector->build_event(thread55).ts(ts).count(1000).commit();
	inspector->build_event(thread75).count(1).commit();
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();

	sinsp_analyzer analyzer(inspector.get(),
	                        "/" /*root dir*/,
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);
	run_sinsp_with_analyzer(*inspector, analyzer);

	std::shared_ptr<flush_data_message> last_flush;
	while (g_queue.get(&last_flush, 0));

	std::shared_ptr<draiosproto::metrics> metrics = last_flush->m_metrics;

	ASSERT_EQ(1, metrics->programs_size());
	ASSERT_EQ(2, metrics->programs(0).pids_size());
	ASSERT_EQ(55, metrics->programs(0).pids(0));
	ASSERT_EQ(75, metrics->programs(0).pids(1));

	// For legacy reasons, the inspector must be deleted before the
	// analyzer.
	inspector.reset();
}

class test_helper
{
public:
	static std::unordered_map<std::string, analyzer_container_state>&
	get_analyzer_containers(sinsp_analyzer& analyzer)
	{
		return analyzer.m_containers;
	}

	static void
	add_inspector_container(sinsp& inspector, const sinsp_container_info& container)
	{
		(*inspector.m_container_manager.m_containers.lock())[container.m_id] =
			std::make_shared<sinsp_container_info>(container);
	}

	static sinsp_container_manager::map_ptr_t
	get_inspector_containers(sinsp& inspector)
	{
		return inspector.m_container_manager.m_containers.lock();
	}

	static void erase_inspector_container(sinsp& inspector, const std::string& name)
	{
		inspector.m_container_manager.m_containers.lock()->erase(name);
	}

	static void coalesce(sinsp_analyzer& analyzer, std::vector<std::string>& emitted)
	{
		analyzer.coalesce_unemitted_stats(emitted);
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
		sinsp_container_info container;
		container.m_id = m_name;
		test_helper::add_inspector_container(inspector, container);
	}

	std::string m_name;
};

// for SMAGENT-1599, ensure we work if the container info is null
TEST(analyzer_test, coalesce_containers_null)
{
	sinsp_mock inspector;
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(&inspector,
	                        "/",
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);
	std::vector<std::string> emitted_containers;
	container_stuff unemitted_container_1(inspector, analyzer, "unemitted_container_1");
	container_stuff unemitted_container_2(inspector, analyzer, "unemitted_container_2");

	// remove container from container manager to simulate it getting deleted
	test_helper::erase_inspector_container(inspector, unemitted_container_2.m_name);

	// coalesce. should crash if broken
	test_helper::coalesce(analyzer, emitted_containers);
	EXPECT_EQ(1, analyzer.metrics()->unreported_counters().names().size());
}

TEST(analyzer_test, coalesce_containers_test)
{
	sinsp_mock inspector;
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(&inspector,
	                        "/",
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);

	std::vector<std::string> emitted_containers;

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
	// memory_limit_kb
	// swap_limit_kb
	{
		sinsp_container_info container;
		container.m_id = emitted_container.m_name;
		container.m_cpu_shares = 5;
		container.m_memory_limit = 5 * 1024;
		container.m_swap_limit = 5 * 1024;
		test_helper::add_inspector_container(inspector, container);
	}
	{
		sinsp_container_info container;
		container.m_id = unemitted_container_1.m_name;
		container.m_cpu_shares = 10;
		container.m_memory_limit = 11 * 1024;
		container.m_swap_limit = 12 * 1024;
		test_helper::add_inspector_container(inspector, container);
	}
	{
		sinsp_container_info container;
		container.m_id = unemitted_container_2.m_name;
		container.m_cpu_shares = 9;
		container.m_memory_limit = 10 * 1024;
		container.m_swap_limit = 11 * 1024;
		test_helper::add_inspector_container(inspector, container);
	}

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

	// syscalls
	test_helper::get_analyzer_containers(analyzer)[emitted_container.m_name].m_metrics.m_metrics.m_unknown.m_count = 5;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_metrics.m_unknown.m_count = 17;
	test_helper::get_analyzer_containers(analyzer)[unemitted_container_2.m_name].m_metrics.m_metrics.m_unknown.m_count = 16;

	// coalesce
	test_helper::coalesce(analyzer, emitted_containers);

	// check that stats are correct in protobuf
	EXPECT_EQ(2, analyzer.metrics()->unreported_counters().resource_counters().connection_queue_usage_pct());
	EXPECT_EQ(5, analyzer.metrics()->unreported_counters().resource_counters().fd_usage_pct());
	EXPECT_EQ(700, analyzer.metrics()->unreported_counters().resource_counters().cpu_pct());
	EXPECT_EQ(9, analyzer.metrics()->unreported_counters().resource_counters().resident_memory_usage_kb());
	EXPECT_EQ(11, analyzer.metrics()->unreported_counters().resource_counters().swap_memory_usage_kb());
	EXPECT_EQ(13, analyzer.metrics()->unreported_counters().resource_counters().major_pagefaults());
	EXPECT_EQ(15, analyzer.metrics()->unreported_counters().resource_counters().minor_pagefaults());
	EXPECT_EQ(17, analyzer.metrics()->unreported_counters().resource_counters().fd_count());
	EXPECT_EQ(19, analyzer.metrics()->unreported_counters().resource_counters().cpu_shares());
	EXPECT_EQ(21, analyzer.metrics()->unreported_counters().resource_counters().memory_limit_kb());
	EXPECT_EQ(23, analyzer.metrics()->unreported_counters().resource_counters().swap_limit_kb());
	EXPECT_EQ(27, analyzer.metrics()->unreported_counters().resource_counters().count_processes());
	EXPECT_EQ(29, analyzer.metrics()->unreported_counters().resource_counters().proc_start_count());
	EXPECT_EQ(31, analyzer.metrics()->unreported_counters().resource_counters().threads_count());
	EXPECT_EQ(33, analyzer.metrics()->unreported_counters().resource_counters().syscall_count());

	// check that we added the names
	EXPECT_EQ(2, analyzer.metrics()->unreported_counters().names().size());

	// check that we cleared the containers
	EXPECT_EQ(test_helper::get_analyzer_containers(analyzer)[unemitted_container_1.m_name].m_metrics.m_connection_queue_usage_pct, 0);
}

TEST(analyzer_test, print_profiling_error)
{
	scoped_config<bool> config("dragent_cpu_profile_enabled", true);
	scoped_sinsp_logger_capture capture;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock());
	auto &tinfo = inspector->build_thread().commit();
	inspector->build_event(tinfo).count(10).commit();

	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
	                        "/",
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);

	// Run the analyzer to induce calling flush
	run_sinsp_with_analyzer(*inspector, analyzer);

	ASSERT_TRUE(capture.find("Profiling is not supported in this build variant."));

	// For legacy reasons, the inspector must be deleted before the
	// analyzer.
	inspector.reset();
}
