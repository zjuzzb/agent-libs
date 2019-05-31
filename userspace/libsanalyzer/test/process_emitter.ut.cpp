/**
 * @file
 *
 * Unit tests for process emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include <gtest.h>
#include "process_emitter.h"
#include "sinsp_mock.h"
#include <unordered_set>
#include <string>
#include <tuple>
#include <stdint.h>
#include "analyzer.h"

class test_helper
{
public:
	template<class Iterator>
	static void filter_top_programs(process_emitter& emitter,
					Iterator progtable_begin,
					Iterator progtable_end,
					bool cs_only,
					uint32_t how_many,
					const std::set<sinsp_threadinfo*>& blacklist,
					std::set<sinsp_threadinfo*>& processes_to_emit)
	{
		emitter.filter_top_programs(progtable_begin,
					    progtable_end,
					    cs_only,
					    how_many,
					    blacklist,
					    processes_to_emit);
	}

	static void set_simpledriver(sinsp_analyzer& analyzer, bool val)
	{
		analyzer.m_simpledriver_enabled = val;
	}

	static void set_proc_filter_rules(process_manager& manager, 
					  std::vector<object_filter_config::filter_rule> rules)
	{
		manager.m_flush_filter.set_rules(rules);
	}

	static void set_config(type_config<uint32_t>& config,
			       uint32_t val)
	{
		config.m_data = val;
	}

	static void set_inspector_mode(sinsp& inspector, scap_mode_t mode)
	{
		inspector.m_mode = mode;
	}
};

class fake_thread : public sinsp_threadinfo
{
public:
	fake_thread()
		: sinsp_threadinfo()
	{
		HASH++;
		m_program_hash = HASH;
		m_pid = HASH;
		m_tid = HASH;
		m_ainfo = new thread_analyzer_info();
		m_ainfo->m_tinfo = this;
		m_ainfo->m_procinfo = new sinsp_procinfo();
		m_ainfo->m_th_analysis_flags = 0;
	}

	~fake_thread()
	{
		delete m_ainfo->m_procinfo;
		m_ainfo->m_procinfo = nullptr;
		delete m_ainfo;
		m_ainfo = nullptr;
	}

	static uint64_t HASH;
};

uint64_t fake_thread::HASH = 0;

// Legacy functionality that should be tested if someone
// modifies that code
TEST(environment_emitter_test, DISABLED_test)
{
}

TEST(jmx_emitter_test, DISABLED_test)
{
}

TEST(app_check_emitter_test, DISABLED_test)
{
}

class easy_process_emitter
{
public:
	easy_process_emitter(bool simpledriver,
			     bool nodriver)
		: m_inspector(),
		  m_process_manager(),
		  m_proc_trc("who knows!", UINT64_MAX - 1),
		  m_device_map(),
		  m_procfs_parser(0, 0, false, 0, 0),
		  m_hash_config(),
		  m_metrics(),
		  m_environment_emitter(0, m_hash_config, m_metrics),
		  m_jmx_metrics(),
		  m_jmx_metrics_by_container(),
		  m_jmx_emitter(m_jmx_metrics, 0, 0, m_jmx_metrics_by_container),
		  m_app_metrics(),
		  m_prom_conf(),
		  m_app_checks_by_container(),
		  m_prometheus_by_container(),
		  m_app_check_emitter(m_app_metrics,
				      0,
				      m_prom_conf,
				      m_app_checks_by_container,
				      m_prometheus_by_container,
				      0),
		  m_process_emitter(m_process_manager,
				    m_inspector,
				    simpledriver,
				    nodriver,
				    m_proc_trc,
				    0,
				    m_device_map,
				    false,
				    false,
				    0,
				    nullptr,
				    nullptr,
				    false,
				    m_procfs_parser,
				    1,
				    1,
				    m_environment_emitter,
				    m_jmx_emitter,
				    m_app_check_emitter)
	{
		test_helper::set_inspector_mode(m_inspector, SCAP_MODE_LIVE);
	}

	process_emitter& operator*()
	{
		return m_process_emitter;
	}

	test_helpers::sinsp_mock m_inspector;
	process_manager m_process_manager;
	tracer_emitter m_proc_trc;
	std::unordered_map<dev_t, std::string> m_device_map;
	sinsp_procfs_parser m_procfs_parser;
	env_hash_config m_hash_config;
	draiosproto::metrics m_metrics;
	environment_emitter m_environment_emitter;
	std::unordered_map<int, java_process> m_jmx_metrics;
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>> m_jmx_metrics_by_container;
	jmx_emitter m_jmx_emitter;
	app_checks_proxy::metric_map_t m_app_metrics;
	prometheus_conf m_prom_conf;
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>> m_app_checks_by_container;
	std::unordered_map<std::string, std::tuple<unsigned, unsigned>> m_prometheus_by_container;
	app_check_emitter m_app_check_emitter;
	process_emitter m_process_emitter;
};

// super basic sanity check. code is legacy and as of yet not really unit tested
TEST(process_emitter_test, emit_process)
{
	easy_process_emitter emitter(false, false);

	fake_thread hi_stats1;
	hi_stats1.m_ainfo->m_cpuload = 100;
	hi_stats1.m_comm = "my_process_name";
	hi_stats1.m_ainfo->m_procinfo->m_cpuload = 100;

	analyzer_emitter::progtable_by_container_t progtable_by_container;
	std::vector<std::string> emitted_containers;

	// set so we skip the top per host
	test_helper::set_config(process_manager::c_top_processes_per_host, 1);
	test_helper::set_config(process_manager::c_process_limit, 1);

	std::set<uint64_t> all_uids;

	sinsp_counter_time tot;
	hi_stats1.m_ainfo->m_procinfo->m_proc_metrics.get_total(&tot);
	(*emitter).emit_process(hi_stats1,
				*emitter.m_metrics.add_programs(),
				progtable_by_container,
				*hi_stats1.m_ainfo->m_procinfo,
				tot,
				emitter.m_metrics,
				all_uids,
				false /*not high priority*/);

	EXPECT_EQ(emitter.m_metrics.programs()[0].procinfo().details().comm(), "my_process_name");
	// low priority process doesn't get a group
	EXPECT_EQ(emitter.m_metrics.programs()[0].program_reporting_group_id().size(), 0);
}

// there are a set of checks before we attempt to sort programs
// that determine whether a process is eligible at all. ensure they all work
TEST(process_emitter_test, filter_top_programs_eligible)
{
	easy_process_emitter emitter(false, false);

	std::set<sinsp_threadinfo*> blacklist;
	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	const analyzer_emitter::progtable_t& progtable_ref = progtable;
	std::set<sinsp_threadinfo*> processes_to_emit;
	fake_thread regular_process;
	progtable.insert(&regular_process);

	// blacklisted processes not included +
	// !simpledriver !cs only
	fake_thread blacklist_process;
	blacklist.insert(&blacklist_process);
	progtable.insert(&blacklist_process);

	test_helper::filter_top_programs(*emitter,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 100,
					 blacklist,
					 processes_to_emit);

	EXPECT_EQ(processes_to_emit.size(), 1);
	EXPECT_NE(processes_to_emit.find(&regular_process), processes_to_emit.end());

	// simpledriver and !cs included
	easy_process_emitter emitter_simpledriver(true, false);
	processes_to_emit.clear();
	test_helper::filter_top_programs(*emitter_simpledriver,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 100,
					 blacklist,
					 processes_to_emit);

	EXPECT_EQ(processes_to_emit.size(), 1);
	EXPECT_NE(processes_to_emit.find(&regular_process), processes_to_emit.end());

	
	// sinpledriver and non-zero net count
	fake_thread net_count_process;
	net_count_process.m_ainfo->m_procinfo->m_proc_metrics.m_net.m_count = 1;

	progtable.insert(&net_count_process);
	processes_to_emit.clear();

	test_helper::filter_top_programs(*emitter_simpledriver,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 true,
					 100,
					 blacklist,
					 processes_to_emit);
	EXPECT_EQ(processes_to_emit.size(), 1); // regular process has 0 new count
	EXPECT_NE(processes_to_emit.find(&net_count_process), processes_to_emit.end());


	// not simpledriver and local/remote IPV4 server/client
	fake_thread local_server;
	local_server.m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER;
	progtable.insert(&local_server);
	fake_thread remote_server;
	remote_server.m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER;
	progtable.insert(&remote_server);
	fake_thread local_client;
	local_client.m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT;
	progtable.insert(&local_client);
	fake_thread remote_client;
	remote_client.m_ainfo->m_th_analysis_flags |= thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT;
	progtable.insert(&remote_client);
	processes_to_emit.clear();

	test_helper::filter_top_programs(*emitter,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 true,
					 100,
					 blacklist,
					 processes_to_emit);

	EXPECT_EQ(processes_to_emit.size(), 4); // have to have flag set
	EXPECT_NE(processes_to_emit.find(&local_server), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&local_client), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&remote_server), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&remote_client), processes_to_emit.end());
}

// validates that of the eligible programs, we return the correct ones based on stat categories
TEST(process_emitter_test, filter_top_programs_stats)
{
	easy_process_emitter emitter(false, false);
	
	std::set<sinsp_threadinfo*> blacklist;
	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	const analyzer_emitter::progtable_t& progtable_ref = progtable;
	std::set<sinsp_threadinfo*> processes_to_emit;

	// CPU
	fake_thread cpu_process;
	cpu_process.m_ainfo->m_cpuload = 100;
	cpu_process.m_ainfo->m_procinfo->m_cpuload = 100;
	progtable.insert(&cpu_process);
	// memory
	fake_thread mem_process;
	mem_process.m_vmsize_kb = 100;
	mem_process.m_ainfo->m_procinfo->m_vmrss_kb = 100;
	progtable.insert(&mem_process);
	// net IO in non-nodriver mode
	fake_thread net_io_process;
	net_io_process.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(100, 100, 100);
	progtable.insert(&net_io_process);
	// disk IO in non-simpledriver
	fake_thread disk_io_process;
	disk_io_process.m_ainfo->m_procinfo->m_proc_metrics.m_io_file.add_in(100, 100, 100);
	progtable.insert(&disk_io_process);

	// bunch of do-nothing processes which have non-zero stats
	fake_thread do_nothing_1;
	do_nothing_1.m_ainfo->m_procinfo->m_cpuload = 5;
	do_nothing_1.m_ainfo->m_procinfo->m_vmrss_kb = 5;
	do_nothing_1.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(5, 5, 5);
	do_nothing_1.m_ainfo->m_procinfo->m_proc_metrics.m_io_file.add_in(5, 5, 5);
	progtable.insert(&do_nothing_1);
	fake_thread do_nothing_2;
	do_nothing_2.m_ainfo->m_procinfo->m_cpuload = 5;
	do_nothing_2.m_ainfo->m_procinfo->m_vmrss_kb = 5;
	do_nothing_2.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(5, 5, 5);
	do_nothing_2.m_ainfo->m_procinfo->m_proc_metrics.m_io_file.add_in(5, 5, 5);
	progtable.insert(&do_nothing_2);

	test_helper::filter_top_programs(*emitter,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 1,
					 blacklist,
					 processes_to_emit);

	EXPECT_EQ(processes_to_emit.size(), 4);
	EXPECT_NE(processes_to_emit.find(&cpu_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&mem_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&net_io_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&disk_io_process), processes_to_emit.end());

	// syscall in simpledriver
	fake_thread syscall_process;
	// needs to have a large value to be larger than the others (we aggregate all of them)
	syscall_process.m_ainfo->m_procinfo->m_proc_metrics.m_other.m_count = 500;
	// needs to have non-zero net io (don't ask me...)
	syscall_process.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(1,1,1);
	progtable.insert(&syscall_process);	
	
	easy_process_emitter emitter_simpledriver(true, false);
	processes_to_emit.clear();
	test_helper::filter_top_programs(*emitter_simpledriver,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 1,
					 blacklist,
					 processes_to_emit);
	EXPECT_EQ(processes_to_emit.size(), 4);
	EXPECT_NE(processes_to_emit.find(&cpu_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&mem_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&net_io_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&syscall_process), processes_to_emit.end());

	easy_process_emitter emitter_nodriver(false, true);
	processes_to_emit.clear();
	test_helper::filter_top_programs(*emitter_nodriver,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 1,
					 blacklist,
					 processes_to_emit);
	EXPECT_EQ(processes_to_emit.size(), 3);
	EXPECT_NE(processes_to_emit.find(&cpu_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&mem_process), processes_to_emit.end());
	EXPECT_NE(processes_to_emit.find(&disk_io_process), processes_to_emit.end());

	// procs with 0 stats not emitted. Need at least to to get
	// past initial check
	fake_thread zero_process;
	progtable.insert(&zero_process);
	fake_thread zero_process_2;
	progtable.insert(&zero_process_2);

	progtable.clear();
	processes_to_emit.clear();
	test_helper::filter_top_programs(*emitter,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 1,
					 blacklist,
					 processes_to_emit);
	EXPECT_EQ(processes_to_emit.size(), 0);
	processes_to_emit.clear();

	test_helper::filter_top_programs(*emitter_simpledriver,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 1,
					 blacklist,
					 processes_to_emit);
	EXPECT_EQ(processes_to_emit.size(), 0);
	processes_to_emit.clear();
	test_helper::filter_top_programs(*emitter_nodriver,
					 progtable_ref.begin(),
					 progtable_ref.end(),
					 false,
					 1,
					 blacklist,
					 processes_to_emit);
	EXPECT_EQ(processes_to_emit.size(), 0);
	processes_to_emit.clear();

}

// validates that some top processes per host are released before everyone else,
// excluding blacklist
TEST(process_emitter_test, top_per_host)
{
	easy_process_emitter emitter(false, false);

	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	std::set<sinsp_threadinfo*> processes_to_emit;

	std::string proc_only_filter = R"(
process:
  flush_filter:
    - include:
        process.name: my_process_name
    - include:
        all
    )";
	yaml_configuration config_yaml(proc_only_filter);
	emitter.m_process_manager.c_process_filter.init(config_yaml);
	ASSERT_EQ(0, config_yaml.errors().size());
	test_helper::set_proc_filter_rules(emitter.m_process_manager, emitter.m_process_manager.c_process_filter.get());


	// create a process with low stats that matches the filter, then one with higher
	// stats that doesn't, and ensure the one that matches the filter gets reported
	// and the other one doesn't

	fake_thread matching_process;
	matching_process.m_comm = "my_process_name";
	progtable.insert(&matching_process);

	fake_thread hi_stats;
	hi_stats.m_ainfo->m_cpuload = 100;
	hi_stats.m_ainfo->m_procinfo->m_cpuload = 100;
	hi_stats.m_vmsize_kb = 100;
	hi_stats.m_ainfo->m_procinfo->m_vmrss_kb = 100;
	hi_stats.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(100, 100, 100);
	hi_stats.m_ainfo->m_procinfo->m_proc_metrics.m_io_file.add_in(100, 100, 100);
	progtable.insert(&hi_stats);

	test_helper::set_config(process_manager::c_top_processes_per_host, 1);
	test_helper::set_config(process_manager::c_process_limit, 1);

	analyzer_emitter::progtable_by_container_t progtable_by_container;
	std::vector<std::string> emitted_containers;
	std::set<uint64_t> all_uids;
	std::set<sinsp_threadinfo*> emitted_processes;
	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);
	
	EXPECT_EQ(emitted_processes.size(), 1);
	EXPECT_NE(emitted_processes.find(&hi_stats), emitted_processes.end());
}

// validates that whitelisted processes are emitted before others
TEST(process_emitter_test, high_priority)
{
	easy_process_emitter emitter(false, false);

	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	std::set<sinsp_threadinfo*> processes_to_emit;

	std::string proc_only_filter = R"(
process:
  flush_filter:
    - include:
        process.name: my_process_name
    - include:
        all
    )";
	yaml_configuration config_yaml(proc_only_filter);
	emitter.m_process_manager.c_process_filter.init(config_yaml);
	ASSERT_EQ(0, config_yaml.errors().size());
	test_helper::set_proc_filter_rules(emitter.m_process_manager, emitter.m_process_manager.c_process_filter.get());


	// create a process with low stats that matches the filter, then one with higher
	// stats that doesn't, and ensure the one that matches the filter gets reported
	// and the other one doesn't

	fake_thread matching_process;
	matching_process.m_comm = "my_process_name";
	progtable.insert(&matching_process);

	fake_thread hi_stats;
	hi_stats.m_ainfo->m_cpuload = 100;
	hi_stats.m_ainfo->m_procinfo->m_cpuload = 100;
	hi_stats.m_vmsize_kb = 100;
	hi_stats.m_ainfo->m_procinfo->m_vmrss_kb = 100;
	hi_stats.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(100, 100, 100);
	hi_stats.m_ainfo->m_procinfo->m_proc_metrics.m_io_file.add_in(100, 100, 100);
	progtable.insert(&hi_stats);

	// set so we skip the top per host
	test_helper::set_config(process_manager::c_top_processes_per_host, 0);
	test_helper::set_config(process_manager::c_process_limit, 1);

	analyzer_emitter::progtable_by_container_t progtable_by_container;
	std::vector<std::string> emitted_containers;
	std::set<uint64_t> all_uids;
	std::set<sinsp_threadinfo*> emitted_processes;
	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);
	
	EXPECT_EQ(emitted_processes.size(), 1);
	EXPECT_NE(emitted_processes.find(&matching_process), emitted_processes.end());

	// repeat test with a process in a container
	std::string proc_container_filter = R"(
process:
  flush_filter:
    - include:
        process.name: my_process_name
        container.name: my_container_name
    - include:
        all
    )";
	yaml_configuration config_yaml_2(proc_container_filter);
	emitter.m_process_manager.c_process_filter.init(config_yaml_2);
	ASSERT_EQ(0, config_yaml_2.errors().size());
	test_helper::set_proc_filter_rules(emitter.m_process_manager, emitter.m_process_manager.c_process_filter.get());

	progtable.clear();
	fake_thread matching_container_process;
	matching_container_process.m_comm = "my_process_name";
	progtable.insert(&matching_container_process);
	sinsp_container_info container;
	container.m_name = "my_container_name";
	container.m_id = "my_container_id";
	progtable_by_container[container.m_id].emplace_back(&matching_container_process);
	emitter.m_inspector.m_container_manager.add_container(container, &matching_container_process);

	progtable.insert(&hi_stats);
	emitted_processes.clear();

	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);

	EXPECT_EQ(emitted_processes.size(), 1);
	EXPECT_NE(emitted_processes.find(&matching_container_process), emitted_processes.end());
}

// validates that emitted processes for a given container are emitted before others
TEST(process_emitter_test, container_procs)
{
	easy_process_emitter emitter(false, false);

	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	std::set<sinsp_threadinfo*> processes_to_emit;

	fake_thread hi_stats;
	hi_stats.m_ainfo->m_cpuload = 100;
	hi_stats.m_ainfo->m_procinfo->m_cpuload = 100;
	hi_stats.m_vmsize_kb = 100;
	hi_stats.m_ainfo->m_procinfo->m_vmrss_kb = 100;
	hi_stats.m_ainfo->m_procinfo->m_proc_metrics.m_io_net.add_in(100, 100, 100);
	hi_stats.m_ainfo->m_procinfo->m_proc_metrics.m_io_file.add_in(100, 100, 100);
	progtable.insert(&hi_stats);

	fake_thread matching_container_process;
	matching_container_process.m_comm = "my_process_name";
	progtable.insert(&matching_container_process);
	sinsp_container_info container;
	container.m_name = "my_container_name";
	container.m_id = "my_container_id";
	analyzer_emitter::progtable_by_container_t progtable_by_container;
	progtable_by_container[container.m_id].emplace_back(&matching_container_process);
	emitter.m_inspector.m_container_manager.add_container(container, &matching_container_process);
	std::vector<std::string> emitted_containers;
	emitted_containers.push_back(container.m_id);

	// set so we skip the top per host
	test_helper::set_config(process_manager::c_top_processes_per_host, 0);
	test_helper::set_config(process_manager::c_process_limit, 1);
	test_helper::set_config(process_manager::c_top_processes_per_container, 1);

	std::set<uint64_t> all_uids;
	std::set<sinsp_threadinfo*> emitted_processes;
	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);
	
	EXPECT_EQ(emitted_processes.size(), 1);
	EXPECT_NE(emitted_processes.find(&matching_container_process), emitted_processes.end());
}

// if we have emitted the top processes per host, per container, and whitelisted processes,
// and still have space left over, we should fill it with more processes from the host level.
// this test verifies that.
TEST(process_emitter_test, other_procs)
{
	easy_process_emitter emitter(false, false);

	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	std::set<sinsp_threadinfo*> processes_to_emit;

	fake_thread hi_stats1;
	hi_stats1.m_ainfo->m_cpuload = 100;
	hi_stats1.m_ainfo->m_procinfo->m_cpuload = 100;
	progtable.insert(&hi_stats1);

	fake_thread hi_stats2;
	hi_stats2.m_ainfo->m_cpuload = 99;
	hi_stats2.m_ainfo->m_procinfo->m_cpuload = 99;
	progtable.insert(&hi_stats2);

	analyzer_emitter::progtable_by_container_t progtable_by_container;
	std::vector<std::string> emitted_containers;

	// set so we skip the top per host
	test_helper::set_config(process_manager::c_top_processes_per_host, 0);
	test_helper::set_config(process_manager::c_process_limit, 8);
	test_helper::set_config(process_manager::c_top_processes_per_container, 0);

	std::set<uint64_t> all_uids;
	std::set<sinsp_threadinfo*> emitted_processes;
	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);

	// the limit gets divided by 8, so we should get max 1 of the extra processes.
	EXPECT_EQ(emitted_processes.size(), 1);
	EXPECT_NE(emitted_processes.find(&hi_stats1), emitted_processes.end());
}

// ensures that we do the right things to each emittable process, namely:
// 1) call emit_process on proper containers
// 2) clear all containers
TEST(process_emitter_test, main_loop)
{
	easy_process_emitter emitter(false, false);

	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	std::set<sinsp_threadinfo*> processes_to_emit;

	fake_thread hi_stats1;
	hi_stats1.m_ainfo->m_cpuload = 100;
	hi_stats1.m_comm = "my_process_name";
	hi_stats1.m_ainfo->m_procinfo->m_cpuload = 100;
	progtable.insert(&hi_stats1);

	fake_thread hi_stats2;
	hi_stats2.m_ainfo->m_cpuload = 99;
	hi_stats2.m_ainfo->m_procinfo->m_cpuload = 99;
	progtable.insert(&hi_stats2);

	analyzer_emitter::progtable_by_container_t progtable_by_container;
	std::vector<std::string> emitted_containers;

	// set so we skip the top per host
	test_helper::set_config(process_manager::c_top_processes_per_host, 1);
	test_helper::set_config(process_manager::c_process_limit, 1);

	std::set<uint64_t> all_uids;
	std::set<sinsp_threadinfo*> emitted_processes;
	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);

	// the limit gets divided by 8, so we should get max 1 of the extra processes.
	// check that the right process is emitted, and populated in the emitted process list
	EXPECT_EQ(emitted_processes.size(), 1);
	EXPECT_NE(emitted_processes.find(&hi_stats1), emitted_processes.end());

	// validates that stats are cleared on the processes
	EXPECT_EQ(hi_stats1.m_ainfo->m_cpuload, 0);
	EXPECT_EQ(hi_stats2.m_ainfo->m_cpuload, 0);

	// validates that protobuf was actually populated
	EXPECT_EQ(emitter.m_metrics.programs()[0].procinfo().details().comm(), "my_process_name");
}

// checks that we set reporting group correctly based on priority
TEST(process_emitter_test, reporting_group)
{
	easy_process_emitter emitter(false, false);

	analyzer_emitter::progtable_t progtable(10,
						sinsp_threadinfo::hasher(),
						sinsp_threadinfo::comparer());
	std::set<sinsp_threadinfo*> processes_to_emit;

	std::string proc_only_filter = R"(
process:
  flush_filter:
    - include:
        process.name: my_process_name
    - include:
        all
    )";
	yaml_configuration config_yaml(proc_only_filter);
	emitter.m_process_manager.c_process_filter.init(config_yaml);
	ASSERT_EQ(0, config_yaml.errors().size());
	test_helper::set_proc_filter_rules(emitter.m_process_manager, emitter.m_process_manager.c_process_filter.get());

	fake_thread matched_process;
	matched_process.m_ainfo->m_cpuload = 1;
	matched_process.m_comm = "my_process_name";
	progtable.insert(&matched_process);

	fake_thread unmatched_process;
	unmatched_process.m_ainfo->m_cpuload = 1;
	unmatched_process.m_comm = "something else";
	progtable.insert(&unmatched_process);

	analyzer_emitter::progtable_by_container_t progtable_by_container;
	std::vector<std::string> emitted_containers;

	test_helper::set_config(process_manager::c_process_limit, 100);

	std::set<uint64_t> all_uids;
	std::set<sinsp_threadinfo*> emitted_processes;
	(*emitter).emit_processes(analyzer_emitter::DF_NONE,
				  progtable,
				  progtable_by_container,
				  emitted_containers,
				  emitter.m_metrics,
				  all_uids,
				  emitted_processes);

	EXPECT_EQ(emitted_processes.size(), 2);
	if (emitter.m_metrics.programs()[0].procinfo().details().comm() == "my_process_name")
	{
		EXPECT_EQ(emitter.m_metrics.programs()[0].program_reporting_group_id().size(), 1);
		EXPECT_EQ(emitter.m_metrics.programs()[1].program_reporting_group_id().size(), 0);
	}
	else
	{
		EXPECT_EQ(emitter.m_metrics.programs()[0].program_reporting_group_id().size(), 0);
		EXPECT_EQ(emitter.m_metrics.programs()[1].program_reporting_group_id().size(), 1);
	}
}
