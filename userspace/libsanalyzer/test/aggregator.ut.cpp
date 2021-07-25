#include "aggregator_limits.h"
#include "aggregator_overrides.h"
#include "draios.helpers.h"
#include "draios.pb.h"
#include "draios.proto.h"
#include "scoped_config.h"

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/message_differencer.h>

#include <fstream>
#include <gperftools/heap-profiler.h>
#include <gperftools/profiler.h>
#include <gtest.h>
#include <iostream>

class test_helper
{
public:
	static std::map<uint32_t, size_t> get_pid_map(metrics_message_aggregator_impl& in)
	{
		return in.pid_map;
	}
};

// What gets tested in each test?
//
// 1) every field EXCEPT non-repeated messages are set, aggregated, verified, modified, then
//    aggregated and verified again.
// 2) if the message contains primary keys, verify that modifying each key of the field will
//    properly affect the comparison
// 3) if the message is included as a singleton field in some OTHER message, verify its
//    aggregator gets called in each of those locations
TEST(aggregator, metrics)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.set_timestamp_ns(1);
	input.set_machine_id("2");
	input.set_customer_id("3");

	// create two IP connections to make sure they both get added
	auto ip = input.add_ipv4_connections();
	ip->set_spid(0);
	ip->set_state(draiosproto::connection_state::CONN_SUCCESS);
	ip = input.add_ipv4_connections();
	ip->set_spid(1);
	ip->set_state(draiosproto::connection_state::CONN_SUCCESS);
	// add one with failure status to make sure it doesn't get aggregated
	ip = input.add_ipv4_connections();
	ip->set_state(draiosproto::connection_state::CONN_FAILED);
	ip = input.add_ipv4_connections();
	ip->set_state(draiosproto::connection_state::CONN_PENDING);

	auto interface = input.add_ipv4_network_interfaces();
	interface->set_addr(0);
	interface = input.add_ipv4_network_interfaces();
	interface->set_addr(1);

	auto program = input.add_programs();
	program->set_environment_hash("0");
	program->set_tiuid(draiosproto::program_java_hasher(*program));
	program = input.add_programs();
	program->set_environment_hash("1");
	program->set_tiuid(draiosproto::program_java_hasher(*program));

	input.set_sampling_ratio(4);
	input.set_host_custom_name("5");
	input.set_host_tags("6");
	input.set_is_host_hidden(false);
	input.set_hidden_processes("7");
	input.set_version("8");

	auto fs = input.add_mounts();
	fs->set_mount_dir("0");
	fs = input.add_mounts();
	fs->set_mount_dir("1");

	auto top_files = input.add_top_files();
	top_files->set_name("0");
	top_files = input.add_top_files();
	top_files->set_name("1");

	input.set_instance_id("9");

	auto container = input.add_containers();
	container->set_id("0");
	container = input.add_containers();
	container->set_id("1");

	auto event = input.add_events();
	event->set_scope("0");
	event = input.add_events();
	event->set_scope("1");

	input.add_config_percentiles(10);
	input.add_config_percentiles(11);

	auto incomplete_interface = input.add_ipv4_incomplete_connections_v2();
	incomplete_interface->set_spid(0);
	incomplete_interface->set_state(draiosproto::connection_state::CONN_FAILED);
	incomplete_interface = input.add_ipv4_incomplete_connections_v2();
	incomplete_interface->set_spid(1);
	incomplete_interface->set_state(draiosproto::connection_state::CONN_PENDING);
	incomplete_interface = input.add_ipv4_incomplete_connections_v2();
	incomplete_interface->set_state(draiosproto::connection_state::CONN_SUCCESS);

	auto user = input.add_userdb();
	user->set_id(0);
	user = input.add_userdb();
	user->set_id(1);

	auto environment = input.add_environments();
	environment->set_hash("0");
	environment = input.add_environments();
	environment->set_hash("1");

	auto top_devices = input.add_top_devices();
	top_devices->set_name("0");
	top_devices = input.add_top_devices();
	top_devices->set_name("1");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.timestamp_ns(), 1);
	EXPECT_EQ(output.machine_id(), "2");
	EXPECT_EQ(output.customer_id(), "3");
	EXPECT_EQ(output.ipv4_connections().size(), 2);
	EXPECT_EQ(output.ipv4_connections()[0].spid(), 0);
	EXPECT_EQ(output.ipv4_connections()[1].spid(), 1);
	EXPECT_EQ(output.ipv4_network_interfaces().size(), 2);
	EXPECT_EQ(output.ipv4_network_interfaces()[0].addr(), 0);
	EXPECT_EQ(output.ipv4_network_interfaces()[1].addr(), 1);
	EXPECT_EQ(output.programs().size(), 2);
	EXPECT_EQ(output.programs()[0].environment_hash(), "0");
	EXPECT_EQ(output.programs()[1].environment_hash(), "1");
	EXPECT_EQ(output.aggr_sampling_ratio().sum(), 4);
	EXPECT_EQ(output.sampling_ratio(), 4);
	EXPECT_EQ(output.host_custom_name(), "5");
	EXPECT_EQ(output.host_tags(), "6");
	EXPECT_EQ(output.is_host_hidden(), false);
	EXPECT_EQ(output.hidden_processes(), "7");
	EXPECT_EQ(output.version(), "8");
	EXPECT_EQ(output.mounts().size(), 2);
	EXPECT_EQ(output.mounts()[0].mount_dir(), "0");
	EXPECT_EQ(output.mounts()[1].mount_dir(), "1");
	EXPECT_EQ(output.top_files().size(), 2);
	EXPECT_EQ(output.top_files()[0].name(), "0");
	EXPECT_EQ(output.top_files()[1].name(), "1");
	EXPECT_EQ(output.instance_id(), "9");
	EXPECT_EQ(output.containers().size(), 2);
	EXPECT_EQ(output.containers()[0].id(), "0");
	EXPECT_EQ(output.containers()[1].id(), "1");
	EXPECT_EQ(output.events().size(), 2);
	EXPECT_EQ(output.events()[0].scope(), "0");
	EXPECT_EQ(output.events()[1].scope(), "1");
	EXPECT_EQ(output.config_percentiles()[0], 10);
	EXPECT_EQ(output.config_percentiles()[1], 11);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2().size(), 2);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[0].spid(), 0);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[1].spid(), 1);
	EXPECT_EQ(output.userdb().size(), 2);
	EXPECT_EQ(output.userdb()[0].id(), 0);
	EXPECT_EQ(output.userdb()[1].id(), 1);
	EXPECT_EQ(output.environments().size(), 2);
	EXPECT_EQ(output.environments()[0].hash(), "0");
	EXPECT_EQ(output.environments()[1].hash(), "1");
	EXPECT_EQ(output.top_devices().size(), 2);
	EXPECT_EQ(output.top_devices()[0].name(), "0");
	EXPECT_EQ(output.top_devices()[1].name(), "1");

	input.set_timestamp_ns(100);
	input.set_machine_id("100");
	input.set_customer_id("100");

	// modify something in the PK, but leave one the same, so we get exactly 1 new entry
	(*input.mutable_ipv4_connections())[1].set_spid(2);
	(*input.mutable_ipv4_network_interfaces())[1].set_addr(2);
	(*input.mutable_programs())[1].set_tiuid(input.programs()[1].tiuid() + 1);

	input.set_sampling_ratio(100);
	input.set_host_custom_name("100");
	input.set_host_tags("100");
	input.set_is_host_hidden(true);
	input.set_hidden_processes("100");
	input.set_version("100");
	(*input.mutable_mounts())[1].set_mount_dir("2");
	(*input.mutable_top_files())[1].set_name("2");
	input.set_instance_id("100");
	(*input.mutable_containers())[1].set_id("2");
	(*input.mutable_events())[1].set_scope("2");
	input.clear_config_percentiles();
	input.add_config_percentiles(100);
	(*input.mutable_ipv4_incomplete_connections_v2())[1].set_spid(2);
	(*input.mutable_userdb())[1].set_id(2);
	(*input.mutable_environments())[1].set_hash("2");
	(*input.mutable_top_devices())[1].set_name("2");

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(output.timestamp_ns(), 1);
	EXPECT_EQ(output.machine_id(), "2");
	EXPECT_EQ(output.customer_id(), "3");
	EXPECT_EQ(output.ipv4_connections().size(), 3);
	EXPECT_EQ(output.ipv4_connections()[0].spid(), 0);
	EXPECT_EQ(output.ipv4_connections()[1].spid(), 1);
	EXPECT_EQ(output.ipv4_connections()[2].spid(), 2);
	EXPECT_EQ(output.ipv4_network_interfaces().size(), 3);
	EXPECT_EQ(output.ipv4_network_interfaces()[0].addr(), 0);
	EXPECT_EQ(output.ipv4_network_interfaces()[1].addr(), 1);
	EXPECT_EQ(output.ipv4_network_interfaces()[2].addr(), 2);
	EXPECT_EQ(output.programs().size(), 3);
	EXPECT_EQ(output.programs()[0].environment_hash(), "0");
	EXPECT_EQ(output.programs()[1].environment_hash(), "1");
	EXPECT_EQ(output.programs()[2].tiuid(), output.programs()[1].tiuid() + 1);
	EXPECT_EQ(output.aggr_sampling_ratio().sum(), 104);
	EXPECT_EQ(output.sampling_ratio(), 4);
	EXPECT_EQ(output.host_custom_name(), "5");
	EXPECT_EQ(output.host_tags(), "6");
	EXPECT_EQ(output.is_host_hidden(), false);
	EXPECT_EQ(output.hidden_processes(), "7");
	EXPECT_EQ(output.version(), "8");
	EXPECT_EQ(output.mounts().size(), 3);
	EXPECT_EQ(output.mounts()[0].mount_dir(), "0");
	EXPECT_EQ(output.mounts()[1].mount_dir(), "1");
	EXPECT_EQ(output.mounts()[2].mount_dir(), "2");
	EXPECT_EQ(output.top_files().size(), 3);
	EXPECT_EQ(output.top_files()[0].name(), "0");
	EXPECT_EQ(output.top_files()[1].name(), "1");
	EXPECT_EQ(output.top_files()[2].name(), "2");
	EXPECT_EQ(output.instance_id(), "9");
	EXPECT_EQ(output.containers().size(), 3);
	EXPECT_EQ(output.containers()[0].id(), "0");
	EXPECT_EQ(output.containers()[1].id(), "1");
	EXPECT_EQ(output.containers()[2].id(), "2");
	EXPECT_EQ(output.events().size(), 3);
	EXPECT_EQ(output.events()[0].scope(), "0");
	EXPECT_EQ(output.events()[1].scope(), "1");
	EXPECT_EQ(output.events()[2].scope(), "2");
	EXPECT_EQ(output.config_percentiles().size(), 1);
	EXPECT_EQ(output.config_percentiles()[0], 100);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2().size(), 3);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[0].spid(), 0);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[1].spid(), 1);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[2].spid(), 2);
	EXPECT_EQ(output.userdb().size(), 3);
	EXPECT_EQ(output.userdb()[0].id(), 0);
	EXPECT_EQ(output.userdb()[1].id(), 1);
	EXPECT_EQ(output.userdb()[2].id(), 2);
	EXPECT_EQ(output.environments().size(), 3);
	EXPECT_EQ(output.environments()[0].hash(), "0");
	EXPECT_EQ(output.environments()[1].hash(), "1");
	EXPECT_EQ(output.environments()[2].hash(), "2");
	EXPECT_EQ(output.top_devices().size(), 3);
	EXPECT_EQ(output.top_devices()[0].name(), "0");
	EXPECT_EQ(output.top_devices()[1].name(), "1");
	EXPECT_EQ(output.top_devices()[2].name(), "2");
}

// check that our string hash function for the pid_map actually produces the correct
// hash. hard-coded hash values come from java 8
TEST(draios_helpers, java_string_hash)
{
	EXPECT_EQ(draiosproto::java_string_hash(""), 0);
	EXPECT_EQ(draiosproto::java_string_hash("a"), 97);
	EXPECT_EQ(draiosproto::java_string_hash("aa"), 3104);
	EXPECT_EQ(draiosproto::java_string_hash("aaa"), 96321);
	EXPECT_EQ(draiosproto::java_string_hash("d309j"), 93919442);
	EXPECT_EQ(draiosproto::java_string_hash("2fadsf;k2j4;kjfdsc89snn32s08j"), -1827656038);
	EXPECT_EQ(draiosproto::java_string_hash("aa", 1), 97);
	EXPECT_EQ(draiosproto::java_string_hash("2fadsf;k2j4;kjfdsc89snn32s08j", 2), 1652);
}

// check that our list hash function for the pid_map actually produces the correct
// hash. hard-coded hash values come from java 8 ArrayList<String>
TEST(draios_helpers, java_list_hash)
{
	// we're just going to use process_details.args as a proxy to get the right type here
	draiosproto::process_details pd;
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 1);
	pd.add_args("");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 31);
	pd.add_args("");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 961);
	pd.add_args("");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 29791);
	pd.clear_args();
	pd.add_args("a");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 128);
	pd.clear_args();
	pd.add_args("aa");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 3135);
	pd.add_args("");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), 97185);
	pd.clear_args();
	pd.add_args("asd;oifj34jf");
	pd.add_args("asodijf");
	pd.add_args("a20uiojfewa");
	pd.add_args("20ofadsjfo;kj");
	EXPECT_EQ(draiosproto::java_list_hash(pd.args()), -1373968058);
}

// Check that our program hash matches the backend produced values. Hard coded values
// obtained by creating protobuf representation of the specified program, and then running
// it through the backend aggregator and observing the value
TEST(draios_helpers, program_hasher)
{
	draiosproto::program comm_only;
	comm_only.mutable_procinfo()->mutable_details()->set_comm("sfdjkl");
	comm_only.mutable_procinfo()->mutable_details()->set_exe("");
	EXPECT_EQ(draiosproto::program_java_hasher(comm_only), 1);

	draiosproto::program exe_only;
	exe_only.mutable_procinfo()->mutable_details()->set_comm("");
	exe_only.mutable_procinfo()->mutable_details()->set_exe("3fuj84");
	EXPECT_EQ(draiosproto::program_java_hasher(exe_only), 1049486109);

	draiosproto::program arg_only;
	arg_only.mutable_procinfo()->mutable_details()->set_comm("");
	arg_only.mutable_procinfo()->mutable_details()->set_exe("");
	arg_only.mutable_procinfo()->mutable_details()->add_args("9034fj8iu");
	EXPECT_EQ(draiosproto::program_java_hasher(arg_only), 1709005703);

	draiosproto::program two_args;
	two_args.mutable_procinfo()->mutable_details()->set_comm("");
	two_args.mutable_procinfo()->mutable_details()->set_exe("");
	two_args.mutable_procinfo()->mutable_details()->add_args("wafuj8");
	two_args.mutable_procinfo()->mutable_details()->add_args("afjiods");
	EXPECT_EQ(draiosproto::program_java_hasher(two_args), 28420948);

	draiosproto::program modified_exe;
	modified_exe.mutable_procinfo()->mutable_details()->set_comm("");
	modified_exe.mutable_procinfo()->mutable_details()->set_exe("3fu: j84");
	EXPECT_EQ(draiosproto::program_java_hasher(modified_exe), 1620991);

	draiosproto::program container_only;
	container_only.mutable_procinfo()->mutable_details()->set_comm("");
	container_only.mutable_procinfo()->mutable_details()->set_exe("");
	container_only.mutable_procinfo()->mutable_details()->set_container_id("a;sdjklf");
	EXPECT_EQ(draiosproto::program_java_hasher(container_only), 1464988871);

	draiosproto::program env_only;
	env_only.mutable_procinfo()->mutable_details()->set_comm("");
	env_only.mutable_procinfo()->mutable_details()->set_exe("");
	env_only.set_environment_hash("asd;lkjf");
	EXPECT_EQ(draiosproto::program_java_hasher(env_only), 18446744072867896965U);

	draiosproto::program everything;
	everything.mutable_procinfo()->mutable_details()->set_comm("comm");
	everything.mutable_procinfo()->mutable_details()->set_exe("exe");
	everything.set_environment_hash("environment_hash");
	everything.mutable_procinfo()->mutable_details()->set_container_id("container_id");
	everything.mutable_procinfo()->mutable_details()->add_args("arg1");
	everything.mutable_procinfo()->mutable_details()->add_args("arg2");
	everything.mutable_procinfo()->mutable_details()->add_args("arg1");
	EXPECT_EQ(draiosproto::program_java_hasher(everything), 1400060730);

	draiosproto::program real_life;
	real_life.mutable_procinfo()->mutable_details()->set_comm("python");
	real_life.mutable_procinfo()->mutable_details()->set_exe(
	    "/sw/external/python27-2.7.1/bin/python");
	real_life.mutable_procinfo()->mutable_details()->add_args(
	    "/sw/ficc/plex-0.129/pylib/ficc/plex//server.py");
	real_life.mutable_procinfo()->mutable_details()->add_args("LT_TKO_SWAP_FARM");
	real_life.mutable_procinfo()->mutable_details()->add_args("--uid");
	real_life.mutable_procinfo()->mutable_details()->add_args("PLPJT9SU9J224DAMS27JWBDGR8G3A");
	real_life.mutable_procinfo()->mutable_details()->set_container_id(
	    "49647f2c_9805_4444_bc44_ce4a87c4175e");
	real_life.add_pids(27329);
	real_life.add_uids(21001);

	EXPECT_EQ(draiosproto::program_java_hasher(real_life), 18446744072762939685U);
}

// ensure that upon aggregating programs, pids are properly inserted into the pid map
TEST(aggregator, pid_map_population)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_programs();

	in->mutable_procinfo()->mutable_details()->set_exe("asdlkfj");
	in->add_pids(1);
	in->add_pids(2);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	auto input2 = input;
	aggregator.aggregate(input2, output, false);
	EXPECT_EQ(test_helper::get_pid_map(aggregator)[1], in->tiuid());
	EXPECT_EQ(test_helper::get_pid_map(aggregator)[2], in->tiuid());

	in->add_pids(3);
	aggregator.aggregate(input, output, false);
	EXPECT_EQ(test_helper::get_pid_map(aggregator)[1], in->tiuid());
	EXPECT_EQ(test_helper::get_pid_map(aggregator)[2], in->tiuid());
	EXPECT_EQ(test_helper::get_pid_map(aggregator)[3], in->tiuid());

	aggregator.reset();
	EXPECT_EQ(test_helper::get_pid_map(aggregator).size(), 0);
}

TEST(aggregator, host)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in_hostinfo = input.mutable_hostinfo();
	auto out_hostinfo = output.mutable_hostinfo();

	in_hostinfo->set_hostname("1");
	in_hostinfo->set_num_cpus(2);
	in_hostinfo->add_cpu_loads(3);
	in_hostinfo->set_physical_memory_size_bytes(4);
	in_hostinfo->set_transaction_processing_delay(5);
	in_hostinfo->add_cpu_steal(6);
	in_hostinfo->set_next_tiers_delay(7);
	in_hostinfo->set_container_start_count(5);

	auto nbp = in_hostinfo->add_network_by_serverports();
	nbp->set_port(0);
	nbp = in_hostinfo->add_network_by_serverports();
	nbp->set_port(1);

	in_hostinfo->add_cpu_idle(8);
	in_hostinfo->set_system_load(8.5);
	in_hostinfo->set_uptime(9);
	in_hostinfo->add_system_cpu(10);
	in_hostinfo->add_user_cpu(11);
	in_hostinfo->set_memory_bytes_available_kb(12);
	in_hostinfo->add_iowait_cpu(13);
	in_hostinfo->add_nice_cpu(14);
	in_hostinfo->set_system_load_1(15);
	in_hostinfo->set_system_load_5(16);
	in_hostinfo->set_system_load_15(17);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(out_hostinfo->hostname(), "1");
	EXPECT_EQ(out_hostinfo->aggr_num_cpus().sum(), 2);
	EXPECT_EQ(out_hostinfo->aggr_cpu_loads().sum()[0], 3);
	EXPECT_EQ(out_hostinfo->aggr_physical_memory_size_bytes().sum(), 4);
	EXPECT_EQ(out_hostinfo->aggr_transaction_processing_delay().sum(), 5);
	EXPECT_EQ(out_hostinfo->aggr_cpu_steal().sum()[0], 6);
	EXPECT_EQ(out_hostinfo->aggr_next_tiers_delay().sum(), 7);
	EXPECT_EQ(out_hostinfo->network_by_serverports().size(), 2);
	EXPECT_EQ(out_hostinfo->network_by_serverports()[0].port(), 0);
	EXPECT_EQ(out_hostinfo->network_by_serverports()[1].port(), 1);
	EXPECT_EQ(out_hostinfo->aggr_cpu_idle().sum()[0], 8);
	EXPECT_EQ(out_hostinfo->aggr_system_load().sum(), 8.5);
	EXPECT_EQ(out_hostinfo->aggr_uptime().sum(), 9);
	EXPECT_EQ(out_hostinfo->aggr_system_cpu().sum()[0], 10);
	EXPECT_EQ(out_hostinfo->aggr_user_cpu().sum()[0], 11);
	EXPECT_EQ(out_hostinfo->aggr_memory_bytes_available_kb().sum(), 12);
	EXPECT_EQ(out_hostinfo->aggr_iowait_cpu().sum()[0], 13);
	EXPECT_EQ(out_hostinfo->aggr_nice_cpu().sum()[0], 14);
	EXPECT_EQ(out_hostinfo->aggr_system_load_1().sum(), 15);
	EXPECT_EQ(out_hostinfo->aggr_system_load_5().sum(), 16);
	EXPECT_EQ(out_hostinfo->aggr_system_load_15().sum(), 17);
	EXPECT_EQ(out_hostinfo->aggr_container_start_count().sum(), 5);

	in_hostinfo->set_hostname("100");
	in_hostinfo->set_num_cpus(100);
	(*in_hostinfo->mutable_cpu_loads())[0] = 100;
	in_hostinfo->set_physical_memory_size_bytes(100);
	in_hostinfo->set_transaction_processing_delay(100);
	(*in_hostinfo->mutable_cpu_steal())[0] = 100;
	in_hostinfo->set_next_tiers_delay(100);
	(*in_hostinfo->mutable_network_by_serverports())[1].set_port(2);
	(*in_hostinfo->mutable_cpu_idle())[0] = 100;
	in_hostinfo->set_system_load(100);
	in_hostinfo->set_uptime(100);
	(*in_hostinfo->mutable_system_cpu())[0] = 100;
	(*in_hostinfo->mutable_user_cpu())[0] = 100;
	in_hostinfo->set_memory_bytes_available_kb(100);
	(*in_hostinfo->mutable_iowait_cpu())[0] = 100;
	(*in_hostinfo->mutable_nice_cpu())[0] = 100;
	in_hostinfo->set_system_load_1(100);
	in_hostinfo->set_system_load_5(100);
	in_hostinfo->set_system_load_15(100);
	in_hostinfo->set_container_start_count(10);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(out_hostinfo->hostname(), "1");
	EXPECT_EQ(out_hostinfo->aggr_num_cpus().sum(), 102);
	EXPECT_EQ(out_hostinfo->aggr_cpu_loads().sum()[0], 103);
	EXPECT_EQ(out_hostinfo->aggr_physical_memory_size_bytes().sum(), 104);
	EXPECT_EQ(out_hostinfo->aggr_transaction_processing_delay().sum(), 105);
	EXPECT_EQ(out_hostinfo->aggr_cpu_steal().sum()[0], 106);
	EXPECT_EQ(out_hostinfo->aggr_next_tiers_delay().sum(), 107);
	EXPECT_EQ(out_hostinfo->network_by_serverports().size(), 3);
	EXPECT_EQ(out_hostinfo->network_by_serverports()[0].port(), 0);
	EXPECT_EQ(out_hostinfo->network_by_serverports()[1].port(), 1);
	EXPECT_EQ(out_hostinfo->network_by_serverports()[2].port(), 2);
	EXPECT_EQ(out_hostinfo->aggr_cpu_idle().sum()[0], 108);
	EXPECT_EQ(out_hostinfo->aggr_system_load().sum(), 108.5);
	EXPECT_EQ(out_hostinfo->aggr_uptime().sum(), 109);
	EXPECT_EQ(out_hostinfo->aggr_system_cpu().sum()[0], 110);
	EXPECT_EQ(out_hostinfo->aggr_user_cpu().sum()[0], 111);
	EXPECT_EQ(out_hostinfo->aggr_memory_bytes_available_kb().sum(), 112);
	EXPECT_EQ(out_hostinfo->aggr_iowait_cpu().sum()[0], 113);
	EXPECT_EQ(out_hostinfo->aggr_nice_cpu().sum()[0], 114);
	EXPECT_EQ(out_hostinfo->aggr_system_load_1().sum(), 115);
	EXPECT_EQ(out_hostinfo->aggr_system_load_5().sum(), 116);
	EXPECT_EQ(out_hostinfo->aggr_system_load_15().sum(), 117);
	EXPECT_EQ(out_hostinfo->aggr_container_start_count().sum(), 15);
}

TEST(aggregator, time_categories)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	// no non-sub message fields, so just have to check that we
	// aggregate properly in each location this message appears
	input.mutable_hostinfo()->mutable_tcounters()->mutable_unknown()->set_count(1);
	input.add_programs()->mutable_procinfo()->mutable_tcounters()->mutable_unknown()->set_count(2);
	input.add_containers()->mutable_tcounters()->mutable_unknown()->set_count(3);
	input.mutable_unreported_counters()->mutable_tcounters()->mutable_unknown()->set_count(4);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(output.hostinfo().tcounters().unknown().aggr_count().sum(), 1);
	EXPECT_EQ(output.programs()[0].procinfo().tcounters().unknown().aggr_count().sum(), 2);
	EXPECT_EQ(output.containers()[0].tcounters().unknown().aggr_count().sum(), 3);
	EXPECT_EQ(output.unreported_counters().tcounters().unknown().aggr_count().sum(), 4);
}

TEST(aggregator, counter_time)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in_ct = input.mutable_hostinfo()->mutable_tcounters()->mutable_unknown();
	auto out_ct = output.mutable_hostinfo()->mutable_tcounters()->mutable_unknown();

	in_ct->set_count(1);
	in_ct->set_time_ns(2);
	in_ct->set_time_percentage(3);

	auto percentile = in_ct->add_percentile();
	percentile->set_percentile(0);
	percentile = in_ct->add_percentile();
	percentile->set_percentile(1);

	// all the places that include counter_time
	input.mutable_hostinfo()->mutable_tcounters()->mutable_other()->set_count(4);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_file()->set_count(5);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_net()->set_count(6);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_ipc()->set_count(7);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_memory()->set_count(8);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_process()->set_count(9);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_sleep()->set_count(10);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_system()->set_count(11);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_signal()->set_count(12);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_user()->set_count(13);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_time()->set_count(14);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_wait()->set_count(15);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_processing()->set_count(16);
	input.mutable_hostinfo()->mutable_reqcounters()->mutable_other()->set_count(17);
	input.mutable_hostinfo()->mutable_reqcounters()->mutable_processing()->set_count(18);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(out_ct->aggr_count().sum(), 1);
	EXPECT_EQ(out_ct->aggr_time_ns().sum(), 2);
	EXPECT_EQ(out_ct->aggr_time_percentage().sum(), 3);
	EXPECT_EQ(out_ct->percentile().size(), 2);
	EXPECT_EQ(out_ct->percentile()[0].percentile(), 0);
	EXPECT_EQ(out_ct->percentile()[1].percentile(), 1);
	EXPECT_EQ(output.hostinfo().tcounters().other().aggr_count().sum(), 4);
	EXPECT_EQ(output.hostinfo().tcounters().file().aggr_count().sum(), 5);
	EXPECT_EQ(output.hostinfo().tcounters().net().aggr_count().sum(), 6);
	EXPECT_EQ(output.hostinfo().tcounters().ipc().aggr_count().sum(), 7);
	EXPECT_EQ(output.hostinfo().tcounters().memory().aggr_count().sum(), 8);
	EXPECT_EQ(output.hostinfo().tcounters().process().aggr_count().sum(), 9);
	EXPECT_EQ(output.hostinfo().tcounters().sleep().aggr_count().sum(), 10);
	EXPECT_EQ(output.hostinfo().tcounters().system().aggr_count().sum(), 11);
	EXPECT_EQ(output.hostinfo().tcounters().signal().aggr_count().sum(), 12);
	EXPECT_EQ(output.hostinfo().tcounters().user().aggr_count().sum(), 13);
	EXPECT_EQ(output.hostinfo().tcounters().time().aggr_count().sum(), 14);
	EXPECT_EQ(output.hostinfo().tcounters().wait().aggr_count().sum(), 15);
	EXPECT_EQ(output.hostinfo().tcounters().processing().aggr_count().sum(), 16);
	EXPECT_EQ(output.hostinfo().reqcounters().other().aggr_count().sum(), 17);
	EXPECT_EQ(output.hostinfo().reqcounters().processing().aggr_count().sum(), 18);

	in_ct->set_count(100);
	in_ct->set_time_ns(100);
	in_ct->set_time_percentage(100);
	(*in_ct->mutable_percentile())[1].set_percentile(100);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(out_ct->aggr_count().sum(), 101);
	EXPECT_EQ(out_ct->aggr_time_ns().sum(), 102);
	EXPECT_EQ(out_ct->aggr_time_percentage().sum(), 103);
	EXPECT_EQ(out_ct->percentile().size(), 3);
	EXPECT_EQ(out_ct->percentile()[0].percentile(), 0);
	EXPECT_EQ(out_ct->percentile()[1].percentile(), 1);
	EXPECT_EQ(out_ct->percentile()[2].percentile(), 100);
}

TEST(aggregator, counter_percentile)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in_cp = input.mutable_hostinfo()->mutable_tcounters()->mutable_unknown()->add_percentile();

	in_cp->set_value(1);

	// all the places that include counter_percentile
	input.mutable_hostinfo()->mutable_tcounters()->mutable_other()->add_percentile()->set_value(2);
	input.mutable_hostinfo()->mutable_transaction_counters()->add_percentile_in()->set_value(3);
	input.mutable_hostinfo()->mutable_transaction_counters()->add_percentile_out()->set_value(4);
	input.mutable_hostinfo()->mutable_external_io_net()->add_percentile_in()->set_value(5);
	input.mutable_hostinfo()->mutable_external_io_net()->add_percentile_out()->set_value(6);
	input.mutable_protos()->mutable_http()->mutable_server_totals()->add_percentile()->set_value(7);
	input.mutable_internal_metrics()->add_statsd_metrics()->add_percentile()->set_value(8);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.hostinfo().tcounters().unknown().percentile()[0].aggr_value().sum(), 1);
	EXPECT_EQ(output.hostinfo().tcounters().other().percentile()[0].aggr_value().sum(), 2);
	EXPECT_EQ(output.hostinfo().transaction_counters().percentile_in()[0].aggr_value().sum(), 3);
	EXPECT_EQ(output.hostinfo().transaction_counters().percentile_out()[0].aggr_value().sum(), 4);
	EXPECT_EQ(output.hostinfo().external_io_net().percentile_in()[0].aggr_value().sum(), 5);
	EXPECT_EQ(output.hostinfo().external_io_net().percentile_out()[0].aggr_value().sum(), 6);
	EXPECT_EQ(output.protos().http().server_totals().percentile()[0].aggr_value().sum(), 7);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].percentile()[0].aggr_value().sum(), 8);

	in_cp->set_value(100);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.hostinfo().tcounters().unknown().percentile()[0].aggr_value().sum(), 101);

	// check primary key
	draiosproto::counter_percentile lhs;
	draiosproto::counter_percentile rhs;

	lhs.set_percentile(1);
	rhs.set_percentile(2);
	EXPECT_FALSE(counter_percentile_message_aggregator::comparer()(&lhs, &rhs));

	rhs.set_percentile(1);
	rhs.set_value(2);
	EXPECT_TRUE(counter_percentile_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(counter_percentile_message_aggregator::hasher()(&lhs),
	          counter_percentile_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, counter_time_bytes)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in_cb = input.mutable_hostinfo()->mutable_external_io_net();
	auto out_cb = output.mutable_hostinfo()->mutable_external_io_net();

	in_cb->set_time_ns_in(1);
	in_cb->set_time_ns_out(2);
	in_cb->set_time_ns_other(3);
	in_cb->set_count_in(4);
	in_cb->set_count_out(5);
	in_cb->set_count_other(6);
	in_cb->set_bytes_in(7);
	in_cb->set_bytes_out(8);
	in_cb->set_bytes_other(9);
	in_cb->set_time_percentage_in(10);
	in_cb->set_time_percentage_out(11);
	in_cb->set_time_percentage_other(12);

	auto percentile = in_cb->add_percentile_in();
	percentile->set_percentile(0);
	percentile = in_cb->add_percentile_in();
	percentile->set_percentile(1);
	percentile = in_cb->add_percentile_out();
	percentile->set_percentile(0);
	percentile = in_cb->add_percentile_out();
	percentile->set_percentile(1);

	// all places counter_time_bytes included
	input.mutable_hostinfo()->mutable_tcounters()->mutable_io_file()->set_time_ns_in(13);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_io_net()->set_time_ns_in(14);
	input.mutable_hostinfo()->mutable_tcounters()->mutable_io_other()->set_time_ns_in(15);
	input.mutable_hostinfo()->mutable_reqcounters()->mutable_io_file()->set_time_ns_in(16);
	input.mutable_hostinfo()->mutable_reqcounters()->mutable_io_net()->set_time_ns_in(17);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(out_cb->aggr_time_ns_in().sum(), 1);
	EXPECT_EQ(out_cb->aggr_time_ns_out().sum(), 2);
	EXPECT_EQ(out_cb->aggr_time_ns_other().sum(), 3);
	EXPECT_EQ(out_cb->aggr_count_in().sum(), 4);
	EXPECT_EQ(out_cb->aggr_count_out().sum(), 5);
	EXPECT_EQ(out_cb->aggr_count_other().sum(), 6);
	EXPECT_EQ(out_cb->aggr_bytes_in().sum(), 7);
	EXPECT_EQ(out_cb->aggr_bytes_out().sum(), 8);
	EXPECT_EQ(out_cb->aggr_bytes_other().sum(), 9);
	EXPECT_EQ(out_cb->aggr_time_percentage_in().sum(), 10);
	EXPECT_EQ(out_cb->aggr_time_percentage_out().sum(), 11);
	EXPECT_EQ(out_cb->aggr_time_percentage_other().sum(), 12);
	EXPECT_EQ(out_cb->percentile_in().size(), 2);
	EXPECT_EQ(out_cb->percentile_in()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_in()[1].percentile(), 1);
	EXPECT_EQ(out_cb->percentile_out().size(), 2);
	EXPECT_EQ(out_cb->percentile_out()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_out()[1].percentile(), 1);
	EXPECT_EQ(output.hostinfo().tcounters().io_file().aggr_time_ns_in().sum(), 13);
	EXPECT_EQ(output.hostinfo().tcounters().io_net().aggr_time_ns_in().sum(), 14);
	EXPECT_EQ(output.hostinfo().tcounters().io_other().aggr_time_ns_in().sum(), 15);
	EXPECT_EQ(output.hostinfo().reqcounters().io_file().aggr_time_ns_in().sum(), 16);
	EXPECT_EQ(output.hostinfo().reqcounters().io_net().aggr_time_ns_in().sum(), 17);

	in_cb->set_time_ns_in(100);
	in_cb->set_time_ns_out(100);
	in_cb->set_time_ns_other(100);
	in_cb->set_count_in(100);
	in_cb->set_count_out(100);
	in_cb->set_count_other(100);
	in_cb->set_bytes_in(100);
	in_cb->set_bytes_out(100);
	in_cb->set_bytes_other(100);
	in_cb->set_time_percentage_in(100);
	in_cb->set_time_percentage_out(100);
	in_cb->set_time_percentage_other(100);
	(*in_cb->mutable_percentile_in())[1].set_percentile(2);
	(*in_cb->mutable_percentile_out())[1].set_percentile(2);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(out_cb->aggr_time_ns_in().sum(), 101);
	EXPECT_EQ(out_cb->aggr_time_ns_out().sum(), 102);
	EXPECT_EQ(out_cb->aggr_time_ns_other().sum(), 103);
	EXPECT_EQ(out_cb->aggr_count_in().sum(), 104);
	EXPECT_EQ(out_cb->aggr_count_out().sum(), 105);
	EXPECT_EQ(out_cb->aggr_count_other().sum(), 106);
	EXPECT_EQ(out_cb->aggr_bytes_in().sum(), 107);
	EXPECT_EQ(out_cb->aggr_bytes_out().sum(), 108);
	EXPECT_EQ(out_cb->aggr_bytes_other().sum(), 109);
	EXPECT_EQ(out_cb->aggr_time_percentage_in().sum(), 110);
	EXPECT_EQ(out_cb->aggr_time_percentage_out().sum(), 111);
	EXPECT_EQ(out_cb->aggr_time_percentage_other().sum(), 112);
	EXPECT_EQ(out_cb->percentile_in().size(), 3);
	EXPECT_EQ(out_cb->percentile_in()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_in()[1].percentile(), 1);
	EXPECT_EQ(out_cb->percentile_in()[2].percentile(), 2);
	EXPECT_EQ(out_cb->percentile_out().size(), 3);
	EXPECT_EQ(out_cb->percentile_out()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_out()[1].percentile(), 1);
	EXPECT_EQ(out_cb->percentile_out()[2].percentile(), 2);
}

TEST(aggregator, counter_time_bidirectional)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in_cb = input.mutable_hostinfo()->mutable_transaction_counters();
	auto out_cb = output.mutable_hostinfo()->mutable_transaction_counters();

	in_cb->set_time_ns_in(1);
	in_cb->set_time_ns_out(2);
	in_cb->set_count_in(4);
	in_cb->set_count_out(5);

	auto percentile = in_cb->add_percentile_in();
	percentile->set_percentile(0);
	percentile = in_cb->add_percentile_in();
	percentile->set_percentile(1);
	percentile = in_cb->add_percentile_out();
	percentile->set_percentile(0);
	percentile = in_cb->add_percentile_out();
	percentile->set_percentile(1);

	// all places counter_time_bytes included
	input.mutable_hostinfo()
	    ->add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->set_time_ns_in(6);
	(*input.mutable_hostinfo()->mutable_network_by_serverports())[0]
	    .mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->set_time_ns_in(7);
	input.mutable_hostinfo()->mutable_max_transaction_counters()->set_time_ns_in(8);
	input.add_programs()->mutable_procinfo()->mutable_transaction_counters()->set_time_ns_in(9);
	(*input.mutable_programs())[0]
	    .mutable_procinfo()
	    ->mutable_max_transaction_counters()
	    ->set_time_ns_in(10);
	input.add_containers()->mutable_transaction_counters()->set_time_ns_in(11);
	(*input.mutable_containers())[0].mutable_max_transaction_counters()->set_time_ns_in(12);
	input.mutable_unreported_counters()->mutable_transaction_counters()->set_time_ns_in(13);
	input.mutable_unreported_counters()->mutable_max_transaction_counters()->set_time_ns_in(14);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(out_cb->aggr_time_ns_in().sum(), 1);
	EXPECT_EQ(out_cb->aggr_time_ns_out().sum(), 2);
	EXPECT_EQ(out_cb->aggr_count_in().sum(), 4);
	EXPECT_EQ(out_cb->aggr_count_out().sum(), 5);
	EXPECT_EQ(out_cb->percentile_in().size(), 2);
	EXPECT_EQ(out_cb->percentile_in()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_in()[1].percentile(), 1);
	EXPECT_EQ(out_cb->percentile_out().size(), 2);
	EXPECT_EQ(out_cb->percentile_out()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_out()[1].percentile(), 1);
	EXPECT_EQ(output.hostinfo()
	              .network_by_serverports()[0]
	              .counters()
	              .transaction_counters()
	              .aggr_time_ns_in()
	              .sum(),
	          6);
	EXPECT_EQ(output.hostinfo()
	              .network_by_serverports()[0]
	              .counters()
	              .max_transaction_counters()
	              .aggr_time_ns_in()
	              .sum(),
	          7);
	EXPECT_EQ(output.hostinfo().max_transaction_counters().aggr_time_ns_in().sum(), 8);
	EXPECT_EQ(output.programs()[0].procinfo().transaction_counters().aggr_time_ns_in().sum(), 9);
	EXPECT_EQ(output.programs()[0].procinfo().max_transaction_counters().aggr_time_ns_in().sum(),
	          10);
	EXPECT_EQ(output.containers()[0].transaction_counters().aggr_time_ns_in().sum(), 11);
	EXPECT_EQ(output.containers()[0].max_transaction_counters().aggr_time_ns_in().sum(), 12);
	EXPECT_EQ(output.unreported_counters().transaction_counters().aggr_time_ns_in().sum(), 13);
	EXPECT_EQ(output.unreported_counters().max_transaction_counters().aggr_time_ns_in().sum(), 14);

	in_cb->set_time_ns_in(100);
	in_cb->set_time_ns_out(100);
	in_cb->set_count_in(100);
	in_cb->set_count_out(100);
	(*in_cb->mutable_percentile_in())[1].set_percentile(2);
	(*in_cb->mutable_percentile_out())[1].set_percentile(2);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(out_cb->aggr_time_ns_in().sum(), 101);
	EXPECT_EQ(out_cb->aggr_time_ns_out().sum(), 102);
	EXPECT_EQ(out_cb->aggr_count_in().sum(), 104);
	EXPECT_EQ(out_cb->aggr_count_out().sum(), 105);
	EXPECT_EQ(out_cb->percentile_in().size(), 3);
	EXPECT_EQ(out_cb->percentile_in()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_in()[1].percentile(), 1);
	EXPECT_EQ(out_cb->percentile_in()[2].percentile(), 2);
	EXPECT_EQ(out_cb->percentile_out().size(), 3);
	EXPECT_EQ(out_cb->percentile_out()[0].percentile(), 0);
	EXPECT_EQ(out_cb->percentile_out()[1].percentile(), 1);
	EXPECT_EQ(out_cb->percentile_out()[2].percentile(), 2);
}

TEST(aggregator, resource_categories)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_hostinfo()->mutable_resource_counters();
	auto out = output.mutable_hostinfo()->mutable_resource_counters();

	in->set_capacity_score(1);
	in->set_stolen_capacity_score(2);
	in->set_connection_queue_usage_pct(3);
	in->set_fd_usage_pct(4);
	in->set_cpu_pct(5);
	in->set_resident_memory_usage_kb(6);
	in->set_virtual_memory_usage_kb(7);
	in->set_swap_memory_usage_kb(8);
	in->set_major_pagefaults(9);
	in->set_minor_pagefaults(10);
	in->set_fd_count(11);
	in->set_cpu_shares(12);
	in->set_memory_limit_kb(13);
	in->set_swap_limit_kb(14);
	in->set_cpu_quota_used_pct(15);
	in->set_swap_memory_total_kb(16);
	in->set_swap_memory_available_kb(17);
	in->set_count_processes(18);
	in->set_proc_start_count(19);
	in->set_jmx_sent(20);
	in->set_jmx_total(21);
	in->set_statsd_sent(22);
	in->set_app_checks_sent(23);
	in->set_app_checks_total(24);
	in->set_threads_count(25);
	in->set_prometheus_sent(26);
	in->set_prometheus_total(27);
	in->set_syscall_count(28);
	in->set_cpu_cores_quota_limit(29);
	in->set_cpu_cpuset_usage_pct(30);
	in->set_cpu_cores_cpuset_limit(31);
	in->set_rw_bytes(32);

	// other locations of resource_categories
	input.add_programs()->mutable_procinfo()->mutable_resource_counters()->set_capacity_score(28);
	input.add_containers()->mutable_resource_counters()->set_capacity_score(29);
	input.mutable_unreported_counters()->mutable_resource_counters()->set_capacity_score(30);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(out->aggr_capacity_score().sum(), 1);
	EXPECT_EQ(out->aggr_stolen_capacity_score().sum(), 2);
	EXPECT_EQ(out->aggr_connection_queue_usage_pct().sum(), 3);
	EXPECT_EQ(out->aggr_fd_usage_pct().sum(), 4);
	EXPECT_EQ(out->aggr_cpu_pct().sum(), 5);
	EXPECT_EQ(out->aggr_resident_memory_usage_kb().sum(), 6);
	EXPECT_EQ(out->aggr_virtual_memory_usage_kb().sum(), 7);
	EXPECT_EQ(out->aggr_swap_memory_usage_kb().sum(), 8);
	EXPECT_EQ(out->aggr_major_pagefaults().sum(), 9);
	EXPECT_EQ(out->aggr_minor_pagefaults().sum(), 10);
	EXPECT_EQ(out->aggr_fd_count().sum(), 11);
	EXPECT_EQ(out->aggr_cpu_shares().sum(), 12);
	EXPECT_EQ(out->aggr_memory_limit_kb().sum(), 13);
	EXPECT_EQ(out->aggr_swap_limit_kb().sum(), 14);
	EXPECT_EQ(out->aggr_cpu_quota_used_pct().sum(), 15);
	EXPECT_EQ(out->aggr_swap_memory_total_kb().sum(), 16);
	EXPECT_EQ(out->aggr_swap_memory_available_kb().sum(), 17);
	EXPECT_EQ(out->aggr_count_processes().sum(), 18);
	EXPECT_EQ(out->aggr_proc_start_count().sum(), 19);
	EXPECT_EQ(out->aggr_jmx_sent().sum(), 20);
	EXPECT_EQ(out->aggr_jmx_total().sum(), 21);
	EXPECT_EQ(out->aggr_statsd_sent().sum(), 22);
	EXPECT_EQ(out->aggr_app_checks_sent().sum(), 23);
	EXPECT_EQ(out->aggr_app_checks_total().sum(), 24);
	EXPECT_EQ(out->aggr_threads_count().sum(), 25);
	EXPECT_EQ(out->aggr_prometheus_sent().sum(), 26);
	EXPECT_EQ(out->aggr_prometheus_total().sum(), 27);
	EXPECT_EQ(out->aggr_syscall_count().sum(), 28);
	EXPECT_EQ(out->aggr_cpu_cores_quota_limit().sum(), 29);
	EXPECT_EQ(out->aggr_cpu_cpuset_usage_pct().sum(), 30);
	EXPECT_EQ(out->aggr_cpu_cores_cpuset_limit().sum(), 31);
	EXPECT_EQ(out->aggr_rw_bytes().sum(), 32);
	EXPECT_EQ(output.programs()[0].procinfo().resource_counters().aggr_capacity_score().sum(), 28);
	EXPECT_EQ(output.containers()[0].resource_counters().aggr_capacity_score().sum(), 29);
	EXPECT_EQ(output.unreported_counters().resource_counters().aggr_capacity_score().sum(), 30);

	in->set_capacity_score(100);
	in->set_stolen_capacity_score(100);
	in->set_connection_queue_usage_pct(100);
	in->set_fd_usage_pct(100);
	in->set_cpu_pct(100);
	in->set_resident_memory_usage_kb(100);
	in->set_virtual_memory_usage_kb(100);
	in->set_swap_memory_usage_kb(100);
	in->set_major_pagefaults(100);
	in->set_minor_pagefaults(100);
	in->set_fd_count(100);
	in->set_cpu_shares(100);
	in->set_memory_limit_kb(100);
	in->set_swap_limit_kb(100);
	in->set_cpu_quota_used_pct(100);
	in->set_swap_memory_total_kb(100);
	in->set_swap_memory_available_kb(100);
	in->set_count_processes(100);
	in->set_proc_start_count(100);
	in->set_jmx_sent(100);
	in->set_jmx_total(100);
	in->set_statsd_sent(100);
	in->set_app_checks_sent(100);
	in->set_app_checks_total(100);
	in->set_threads_count(100);
	in->set_prometheus_sent(100);
	in->set_prometheus_total(100);
	in->set_syscall_count(100);
	in->set_cpu_cores_quota_limit(100);
	in->set_cpu_cpuset_usage_pct(100);
	in->set_cpu_cores_cpuset_limit(100);
	in->set_rw_bytes(100);

	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(out->aggr_capacity_score().sum(), 101);
	EXPECT_EQ(out->aggr_stolen_capacity_score().sum(), 102);
	EXPECT_EQ(out->aggr_connection_queue_usage_pct().sum(), 103);
	EXPECT_EQ(out->aggr_fd_usage_pct().sum(), 104);
	EXPECT_EQ(out->aggr_cpu_pct().sum(), 105);
	EXPECT_EQ(out->aggr_resident_memory_usage_kb().sum(), 106);
	EXPECT_EQ(out->aggr_virtual_memory_usage_kb().sum(), 107);
	EXPECT_EQ(out->aggr_swap_memory_usage_kb().sum(), 108);
	EXPECT_EQ(out->aggr_major_pagefaults().sum(), 109);
	EXPECT_EQ(out->aggr_minor_pagefaults().sum(), 110);
	EXPECT_EQ(out->aggr_fd_count().sum(), 111);
	EXPECT_EQ(out->aggr_cpu_shares().sum(), 112);
	EXPECT_EQ(out->aggr_memory_limit_kb().sum(), 113);
	EXPECT_EQ(out->aggr_swap_limit_kb().sum(), 114);
	EXPECT_EQ(out->aggr_cpu_quota_used_pct().sum(), 115);
	EXPECT_EQ(out->aggr_swap_memory_total_kb().sum(), 116);
	EXPECT_EQ(out->aggr_swap_memory_available_kb().sum(), 117);
	EXPECT_EQ(out->aggr_count_processes().sum(), 118);
	EXPECT_EQ(out->aggr_proc_start_count().sum(), 119);
	EXPECT_EQ(out->aggr_jmx_sent().sum(), 120);
	EXPECT_EQ(out->aggr_jmx_total().sum(), 121);
	EXPECT_EQ(out->aggr_statsd_sent().sum(), 122);
	EXPECT_EQ(out->aggr_app_checks_sent().sum(), 123);
	EXPECT_EQ(out->aggr_app_checks_total().sum(), 124);
	EXPECT_EQ(out->aggr_threads_count().sum(), 125);
	EXPECT_EQ(out->aggr_prometheus_sent().sum(), 126);
	EXPECT_EQ(out->aggr_prometheus_total().sum(), 127);
	EXPECT_EQ(out->aggr_syscall_count().sum(), 128);
	EXPECT_EQ(out->aggr_cpu_cores_quota_limit().sum(), 129);
	EXPECT_EQ(out->aggr_cpu_cpuset_usage_pct().sum(), 130);
	EXPECT_EQ(out->aggr_cpu_cores_cpuset_limit().sum(), 131);
	EXPECT_EQ(out->aggr_rw_bytes().sum(), 132);

	// we have to ignore "invalid" capacity scores
	// We use this number rather than the computation to
	// be absolutly sure it produces the same number as the BE.
	uint32_t invalid_capacity_score = 4294967196;
	in->set_capacity_score(invalid_capacity_score);
	in->set_stolen_capacity_score(invalid_capacity_score);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(out->aggr_capacity_score().sum(), 101);
	EXPECT_EQ(out->aggr_stolen_capacity_score().sum(), 102);
}

TEST(aggregator, stolen_capacity_score)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::resource_categories>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::resource_categories>>(
	        &builder.build_resource_categories());

	draiosproto::resource_categories input;
	draiosproto::resource_categories output;

	// this test because of a bug which was found where an unset capacity score
	// caused stolen capacity score to not get aggregated
	input.set_stolen_capacity_score(1);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.aggr_stolen_capacity_score().sum(), 1);
}

TEST(aggregator, counter_syscall_errors)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_hostinfo()->mutable_syscall_errors();
	auto out = output.mutable_hostinfo()->mutable_syscall_errors();

	in->set_count(1);
	in->add_top_error_codes(0);
	in->add_top_error_codes(1);
	in->set_count_file(2);
	in->set_count_file_open(3);
	in->set_count_net(4);

	// other locations of resource_categories
	input.add_programs()->mutable_procinfo()->mutable_syscall_errors()->set_count(5);
	input.add_containers()->mutable_syscall_errors()->set_count(6);
	input.mutable_unreported_counters()->mutable_syscall_errors()->set_count(7);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(out->aggr_count().sum(), 1);
	EXPECT_EQ(out->top_error_codes().size(), 2);
	EXPECT_EQ(out->top_error_codes()[0], 0);
	EXPECT_EQ(out->top_error_codes()[1], 1);
	EXPECT_EQ(out->aggr_count_file().sum(), 2);
	EXPECT_EQ(out->aggr_count_file_open().sum(), 3);
	EXPECT_EQ(out->aggr_count_net().sum(), 4);
	EXPECT_EQ(output.programs()[0].procinfo().syscall_errors().aggr_count().sum(), 5);
	EXPECT_EQ(output.containers()[0].syscall_errors().aggr_count().sum(), 6);
	EXPECT_EQ(output.unreported_counters().syscall_errors().aggr_count().sum(), 7);

	in->set_count(100);
	in->set_count_file(100);
	in->set_count_file_open(100);
	in->set_count_net(100);
	(*in->mutable_top_error_codes())[1] = 2;

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(out->aggr_count().sum(), 101);
	EXPECT_EQ(out->top_error_codes().size(), 3);
	EXPECT_EQ(out->top_error_codes()[0], 0);
	EXPECT_EQ(out->top_error_codes()[1], 1);
	EXPECT_EQ(out->top_error_codes()[2], 2);
	EXPECT_EQ(out->aggr_count_file().sum(), 102);
	EXPECT_EQ(out->aggr_count_file_open().sum(), 103);
	EXPECT_EQ(out->aggr_count_net().sum(), 104);
}

TEST(aggregator, transaction_breakdown_categories)
{
	// only contains non-repeated sub-message types. so only need to test that it
	// gets called appropriately
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.mutable_hostinfo()->mutable_reqcounters()->mutable_other()->set_count(1);
	input.add_containers()->mutable_reqcounters()->mutable_other()->set_count(2);
	input.mutable_unreported_counters()->mutable_reqcounters()->mutable_other()->set_count(3);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.hostinfo().reqcounters().other().aggr_count().sum(), 1);
	EXPECT_EQ(output.containers()[0].reqcounters().other().aggr_count().sum(), 2);
	EXPECT_EQ(output.unreported_counters().reqcounters().other().aggr_count().sum(), 3);
}

TEST(aggregator, network_by_port)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	// all the places that include counter_percentile
	input.mutable_hostinfo()->add_network_by_serverports()->set_port(1);
	input.add_containers()->add_network_by_serverports()->set_port(2);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(output.hostinfo().network_by_serverports()[0].port(), 1);
	EXPECT_EQ(output.containers()[0].network_by_serverports()[0].port(), 2);

	// check primary key
	draiosproto::network_by_port lhs;
	draiosproto::network_by_port rhs;

	lhs.set_port(1);
	rhs.set_port(2);
	EXPECT_FALSE(network_by_port_message_aggregator::comparer()(&lhs, &rhs));

	rhs.set_port(1);
	rhs.mutable_counters()->set_n_aggregated_connections(2);
	EXPECT_TRUE(network_by_port_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(network_by_port_message_aggregator::hasher()(&lhs),
	          network_by_port_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, connection_categories)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_hostinfo()->add_network_by_serverports()->mutable_counters();

	in->set_n_aggregated_connections(1);

	// other locations of connection_categories
	input.add_ipv4_connections()->mutable_counters()->set_n_aggregated_connections(2);
	(*input.mutable_ipv4_connections())[0].set_state(draiosproto::connection_state::CONN_SUCCESS);
	input.add_ipv4_incomplete_connections_v2()->mutable_counters()->set_n_aggregated_connections(3);
	(*input.mutable_ipv4_incomplete_connections_v2())[0].set_state(
	    draiosproto::connection_state::CONN_FAILED);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.hostinfo()
	              .network_by_serverports()[0]
	              .counters()
	              .aggr_n_aggregated_connections()
	              .sum(),
	          1);
	EXPECT_EQ(output.ipv4_connections()[0].counters().aggr_n_aggregated_connections().sum(), 2);
	EXPECT_EQ(
	    output.ipv4_incomplete_connections_v2()[0].counters().aggr_n_aggregated_connections().sum(),
	    3);

	in->set_n_aggregated_connections(100);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.hostinfo()
	              .network_by_serverports()[0]
	              .counters()
	              .aggr_n_aggregated_connections()
	              .sum(),
	          101);
}

TEST(aggregator, counter_bytes)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_hostinfo()
	              ->add_network_by_serverports()
	              ->mutable_counters()
	              ->mutable_server();

	in->set_count_in(1);
	in->set_count_out(2);
	in->set_bytes_in(3);
	in->set_bytes_out(4);

	// other locations of counter_bytes
	(*input.mutable_hostinfo()->mutable_network_by_serverports())[0]
	    .mutable_counters()
	    ->mutable_client()
	    ->set_count_in(5);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_count_in().sum(),
	    1);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_count_out().sum(),
	    2);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_bytes_in().sum(),
	    3);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_bytes_out().sum(),
	    4);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().client().aggr_count_in().sum(),
	    5);

	in->set_count_in(100);
	in->set_count_out(100);
	in->set_bytes_in(100);
	in->set_bytes_out(100);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_count_in().sum(),
	    101);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_count_out().sum(),
	    102);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_bytes_in().sum(),
	    103);
	EXPECT_EQ(
	    output.hostinfo().network_by_serverports()[0].counters().server().aggr_bytes_out().sum(),
	    104);
}

TEST(aggregator, ipv4_connection)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_ipv4_connections();

	in->set_spid(1);
	in->set_dpid(2);
	in->mutable_counters()->set_n_aggregated_connections(1);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.ipv4_connections().size(), 1);
	EXPECT_EQ(output.ipv4_connections()[0].counters().aggr_n_aggregated_connections().sum(), 1);
	EXPECT_EQ(output.ipv4_connections()[0].spid(), 1);
	EXPECT_EQ(output.ipv4_connections()[0].dpid(), 2);

	// we have special handling for non-successful connections
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	in = input.add_ipv4_connections();
	in->set_spid(2);
	in->set_dpid(2);
	in->mutable_counters()->set_n_aggregated_connections(1);
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.ipv4_connections().size(), 2);
	EXPECT_EQ(output.ipv4_connections()[0].counters().aggr_n_aggregated_connections().sum(), 1);
	EXPECT_EQ(output.ipv4_connections()[1].counters().aggr_n_aggregated_connections().sum(), 0);

	// check primary key
	draiosproto::ipv4_connection lhs;
	draiosproto::ipv4_connection rhs;

	rhs.set_spid(1);
	EXPECT_FALSE(ipv4_connection_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_spid(0);
	rhs.set_dpid(1);
	EXPECT_FALSE(ipv4_connection_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_dpid(0);
	rhs.mutable_tuple()->set_sip(1);
	EXPECT_FALSE(ipv4_connection_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_tuple()->set_sip(0);

	rhs.mutable_counters()->set_n_aggregated_connections(2);
	rhs.set_state((draiosproto::connection_state)1);
	rhs.set_error_code((draiosproto::error_code)1);
	EXPECT_TRUE(ipv4_connection_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(ipv4_connection_message_aggregator::hasher()(&lhs),
	          ipv4_connection_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, ipv4tuple)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_ipv4_connections()->mutable_tuple();

	in->set_sip(1);
	in->set_dip(2);
	in->set_sport(3);
	in->set_dport(4);
	in->set_l4proto(5);
	(*input.mutable_ipv4_connections())[0].set_state(draiosproto::connection_state::CONN_SUCCESS);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(output.ipv4_connections()[0].tuple().sip(), 1);
	EXPECT_EQ(output.ipv4_connections()[0].tuple().dip(), 2);
	EXPECT_EQ(output.ipv4_connections()[0].tuple().sport(), 3);
	EXPECT_EQ(output.ipv4_connections()[0].tuple().dport(), 4);
	EXPECT_EQ(output.ipv4_connections()[0].tuple().l4proto(), 5);

	// check primary key
	draiosproto::ipv4tuple lhs;
	draiosproto::ipv4tuple rhs;

	rhs.set_sip(1);
	EXPECT_FALSE(ipv4tuple_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_sip(0);
	rhs.set_dip(1);
	EXPECT_FALSE(ipv4tuple_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_dip(0);
	rhs.set_sport(1);
	EXPECT_FALSE(ipv4tuple_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_sport(0);
	rhs.set_dport(1);
	EXPECT_FALSE(ipv4tuple_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_dport(0);
	rhs.set_l4proto(1);
	EXPECT_FALSE(ipv4tuple_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_l4proto(0);

	EXPECT_TRUE(ipv4tuple_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(ipv4tuple_message_aggregator::hasher()(&lhs),
	          ipv4tuple_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, ipv4_incomplete_connection)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_ipv4_incomplete_connections_v2();

	in->set_spid(1);
	in->set_dpid(2);
	in->mutable_counters()->set_n_aggregated_connections(1);
	in->set_state(draiosproto::connection_state::CONN_FAILED);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.ipv4_incomplete_connections_v2().size(), 1);
	EXPECT_EQ(
	    output.ipv4_incomplete_connections_v2()[0].counters().aggr_n_aggregated_connections().sum(),
	    1);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[0].spid(), 1);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[0].dpid(), 2);

	// we have special handling for non-successful connections
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	in = input.add_ipv4_incomplete_connections_v2();
	in->set_spid(2);
	in->set_dpid(2);
	in->mutable_counters()->set_n_aggregated_connections(1);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2().size(), 2);
	EXPECT_EQ(
	    output.ipv4_incomplete_connections_v2()[0].counters().aggr_n_aggregated_connections().sum(),
	    1);
	EXPECT_EQ(
	    output.ipv4_incomplete_connections_v2()[1].counters().aggr_n_aggregated_connections().sum(),
	    0);

	// check primary key
	draiosproto::ipv4_incomplete_connection lhs;
	draiosproto::ipv4_incomplete_connection rhs;

	rhs.set_spid(1);
	EXPECT_FALSE(ipv4_incomplete_connection_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_spid(0);
	rhs.mutable_tuple()->set_sip(1);
	EXPECT_FALSE(ipv4_incomplete_connection_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_tuple()->set_sip(0);

	rhs.mutable_counters()->set_n_aggregated_connections(2);
	rhs.set_state((draiosproto::connection_state)1);
	rhs.set_error_code((draiosproto::error_code)1);
	rhs.set_dpid(1);
	EXPECT_TRUE(ipv4_incomplete_connection_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(ipv4_incomplete_connection_message_aggregator::hasher()(&lhs),
	          ipv4_incomplete_connection_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, ipv4_network_interface)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_ipv4_network_interfaces();

	in->set_name("1");
	in->set_addr(2);
	in->set_netmask(3);
	in->set_bcast(4);

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(output.ipv4_network_interfaces()[0].name(), "1");
	EXPECT_EQ(output.ipv4_network_interfaces()[0].addr(), 2);
	EXPECT_EQ(output.ipv4_network_interfaces()[0].netmask(), 3);
	EXPECT_EQ(output.ipv4_network_interfaces()[0].bcast(), 4);

	// check primary key
	draiosproto::ipv4_network_interface lhs;
	draiosproto::ipv4_network_interface rhs;

	rhs.set_addr(1);
	EXPECT_FALSE(ipv4_network_interface_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_addr(0);
	rhs.set_netmask(1);
	EXPECT_FALSE(ipv4_network_interface_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_netmask(0);
	rhs.set_bcast(1);
	EXPECT_FALSE(ipv4_network_interface_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_bcast(0);

	rhs.set_name("1");
	EXPECT_TRUE(ipv4_network_interface_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(ipv4_network_interface_message_aggregator::hasher()(&lhs),
	          ipv4_network_interface_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, program)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_programs();

	in->add_pids(1);
	in->add_pids(2);
	in->add_uids(3);
	in->add_uids(4);
	in->set_environment_hash("5");
	in->add_program_reporting_group_id(6);
	in->add_program_reporting_group_id(7);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	auto input3 = input;
	aggregator->aggregate(input3, output, false);

	EXPECT_EQ(output.programs()[0].pids().size(), 1);
	EXPECT_EQ(output.programs()[0].pids()[0], output.programs()[0].tiuid());
	EXPECT_EQ(output.programs()[0].uids().size(), 2);
	EXPECT_EQ(output.programs()[0].uids()[0], 3);
	EXPECT_EQ(output.programs()[0].uids()[1], 4);
	EXPECT_EQ(output.programs()[0].environment_hash(), "5");
	EXPECT_EQ(output.programs()[0].program_reporting_group_id().size(), 2);
	EXPECT_EQ(output.programs()[0].program_reporting_group_id()[0], 6);
	EXPECT_EQ(output.programs()[0].program_reporting_group_id()[1], 7);

	(*in->mutable_uids())[1] = 5;
	(*in->mutable_program_reporting_group_id())[1] = 8;

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.programs()[0].uids().size(), 3);
	EXPECT_EQ(output.programs()[0].uids()[0], 3);
	EXPECT_EQ(output.programs()[0].uids()[1], 4);
	EXPECT_EQ(output.programs()[0].uids()[2], 5);
	EXPECT_EQ(output.programs()[0].program_reporting_group_id().size(), 3);
	EXPECT_EQ(output.programs()[0].program_reporting_group_id()[0], 6);
	EXPECT_EQ(output.programs()[0].program_reporting_group_id()[1], 7);
	EXPECT_EQ(output.programs()[0].program_reporting_group_id()[2], 8);

	// check primary key
	draiosproto::program lhs;
	draiosproto::program rhs;

	rhs.set_tiuid(1);
	EXPECT_FALSE(program_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_tiuid(0);

	rhs.add_pids(1);
	rhs.add_uids(1);
	rhs.mutable_procinfo()->mutable_details()->set_exe("");
	rhs.mutable_procinfo()->mutable_details()->add_args("1");
	rhs.set_environment_hash("");
	rhs.add_program_reporting_group_id(1);
	rhs.mutable_procinfo()->mutable_details()->set_container_id("1");
	EXPECT_TRUE(program_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(program_message_aggregator::hasher()(&lhs),
	          program_message_aggregator::hasher()(&rhs));

	// custom hash stuff, check that key isn't added multiple times
	draiosproto::metrics input2;
	draiosproto::metrics output2;
	input2.add_programs();
	input2.add_programs();
	aggregator->reset();
	aggregator->aggregate(input2, output2, false);
	EXPECT_EQ(output.programs().size(), 1);
	EXPECT_EQ(output.programs()[0].pids().size(), 1);
}

TEST(aggregator, process)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_programs()->mutable_procinfo();

	in->set_transaction_processing_delay(1);
	in->set_next_tiers_delay(2);
	in->set_netrole(3);
	in->set_start_count(4);
	in->set_count_processes(5);

	auto top_files = in->add_top_files();
	top_files->set_name("0");
	top_files = in->add_top_files();
	top_files->set_name("1");

	auto top_devices = in->add_top_devices();
	top_devices->set_name("0");
	top_devices = in->add_top_devices();
	top_devices->set_name("1");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.programs()[0].procinfo().aggr_transaction_processing_delay().sum(), 1);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_next_tiers_delay().sum(), 2);
	EXPECT_EQ(output.programs()[0].procinfo().netrole(), 3);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_start_count().sum(), 4);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_count_processes().sum(), 5);
	EXPECT_EQ(output.programs()[0].procinfo().top_files().size(), 2);
	EXPECT_EQ(output.programs()[0].procinfo().top_files()[0].name(), "0");
	EXPECT_EQ(output.programs()[0].procinfo().top_files()[1].name(), "1");
	EXPECT_EQ(output.programs()[0].procinfo().top_devices().size(), 2);
	EXPECT_EQ(output.programs()[0].procinfo().top_devices()[0].name(), "0");
	EXPECT_EQ(output.programs()[0].procinfo().top_devices()[1].name(), "1");

	in->set_transaction_processing_delay(100);
	in->set_next_tiers_delay(100);
	in->set_netrole(100);
	in->set_start_count(100);
	in->set_count_processes(100);
	(*in->mutable_top_files())[1].set_name("2");
	(*in->mutable_top_devices())[1].set_name("2");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_transaction_processing_delay().sum(), 101);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_next_tiers_delay().sum(), 102);
	EXPECT_EQ(output.programs()[0].procinfo().netrole(), 3 | 100);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_start_count().sum(), 104);
	EXPECT_EQ(output.programs()[0].procinfo().aggr_count_processes().sum(), 105);
	EXPECT_EQ(output.programs()[0].procinfo().top_files().size(), 3);
	EXPECT_EQ(output.programs()[0].procinfo().top_files()[0].name(), "0");
	EXPECT_EQ(output.programs()[0].procinfo().top_files()[1].name(), "1");
	EXPECT_EQ(output.programs()[0].procinfo().top_files()[2].name(), "2");
	EXPECT_EQ(output.programs()[0].procinfo().top_devices().size(), 3);
	EXPECT_EQ(output.programs()[0].procinfo().top_devices()[0].name(), "0");
	EXPECT_EQ(output.programs()[0].procinfo().top_devices()[1].name(), "1");
	EXPECT_EQ(output.programs()[0].procinfo().top_devices()[2].name(), "2");
}

TEST(aggregator, process_details)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_programs()->mutable_procinfo()->mutable_details();

	in->set_comm("1");
	in->set_exe("2");
	in->add_args("3");
	in->add_args("4");
	in->add_args("3");  // can have duplicate args. need all of them!
	in->set_container_id("5");
	(*input.mutable_programs())[0].set_tiuid(1);

	// backend auto-populates the container_id...so we do too!
	input.add_programs()->mutable_procinfo()->mutable_details();

	aggregator->aggregate(input, output, false);

	EXPECT_EQ(output.programs()[0].procinfo().details().comm(), "1");
	EXPECT_EQ(output.programs()[0].procinfo().details().exe(), "2");
	EXPECT_EQ(output.programs()[0].procinfo().details().args().size(), 3);
	EXPECT_EQ(output.programs()[0].procinfo().details().args()[0], "3");
	EXPECT_EQ(output.programs()[0].procinfo().details().args()[1], "4");
	EXPECT_EQ(output.programs()[0].procinfo().details().args()[2], "3");
	EXPECT_EQ(output.programs()[0].procinfo().details().container_id(), "5");
	EXPECT_EQ(output.programs()[1].procinfo().details().container_id(), "");
}

TEST(aggregator, proto_info)
{
	// only contains non-repeated sub-message types. so only need to test that it
	// gets called appropriately
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.add_programs()->mutable_procinfo()->mutable_protos()->mutable_java()->set_process_name(
	    "1");
	input.add_containers()->mutable_protos()->mutable_java()->set_process_name("2");
	input.mutable_unreported_counters()->mutable_protos()->mutable_java()->set_process_name("3");
	input.mutable_protos()->mutable_java()->set_process_name("4");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.programs()[0].procinfo().protos().java().process_name(), "1");
	EXPECT_EQ(output.containers()[0].protos().java().process_name(), "2");
	EXPECT_EQ(output.unreported_counters().protos().java().process_name(), "3");
	EXPECT_EQ(output.protos().java().process_name(), "4");
}

TEST(aggregator, http_info)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.mutable_protos()->mutable_http()->add_server_urls()->set_url("1");
	input.mutable_protos()->mutable_http()->add_server_urls()->set_url("2");
	input.mutable_protos()->mutable_http()->add_client_urls()->set_url("3");
	input.mutable_protos()->mutable_http()->add_client_urls()->set_url("4");
	input.mutable_protos()->mutable_http()->add_server_status_codes()->set_status_code(5);
	input.mutable_protos()->mutable_http()->add_server_status_codes()->set_status_code(6);
	input.mutable_protos()->mutable_http()->add_client_status_codes()->set_status_code(7);
	input.mutable_protos()->mutable_http()->add_client_status_codes()->set_status_code(8);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().http().server_urls().size(), 2);
	EXPECT_EQ(output.protos().http().server_urls()[0].url(), "1");
	EXPECT_EQ(output.protos().http().server_urls()[1].url(), "2");
	EXPECT_EQ(output.protos().http().client_urls().size(), 2);
	EXPECT_EQ(output.protos().http().client_urls()[0].url(), "3");
	EXPECT_EQ(output.protos().http().client_urls()[1].url(), "4");
	EXPECT_EQ(output.protos().http().server_status_codes().size(), 2);
	EXPECT_EQ(output.protos().http().server_status_codes()[0].status_code(), 5);
	EXPECT_EQ(output.protos().http().server_status_codes()[1].status_code(), 6);
	EXPECT_EQ(output.protos().http().client_status_codes().size(), 2);
	EXPECT_EQ(output.protos().http().client_status_codes()[0].status_code(), 7);
	EXPECT_EQ(output.protos().http().client_status_codes()[1].status_code(), 8);

	(*input.mutable_protos()->mutable_http()->mutable_server_urls())[1].set_url("9");
	(*input.mutable_protos()->mutable_http()->mutable_client_urls())[1].set_url("10");
	(*input.mutable_protos()->mutable_http()->mutable_server_status_codes())[1].set_status_code(11);
	(*input.mutable_protos()->mutable_http()->mutable_client_status_codes())[1].set_status_code(12);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().http().server_urls().size(), 3);
	EXPECT_EQ(output.protos().http().server_urls()[0].url(), "1");
	EXPECT_EQ(output.protos().http().server_urls()[1].url(), "2");
	EXPECT_EQ(output.protos().http().server_urls()[2].url(), "9");
	EXPECT_EQ(output.protos().http().client_urls().size(), 3);
	EXPECT_EQ(output.protos().http().client_urls()[0].url(), "3");
	EXPECT_EQ(output.protos().http().client_urls()[1].url(), "4");
	EXPECT_EQ(output.protos().http().client_urls()[2].url(), "10");
	EXPECT_EQ(output.protos().http().server_status_codes().size(), 3);
	EXPECT_EQ(output.protos().http().server_status_codes()[0].status_code(), 5);
	EXPECT_EQ(output.protos().http().server_status_codes()[1].status_code(), 6);
	EXPECT_EQ(output.protos().http().server_status_codes()[2].status_code(), 11);
	EXPECT_EQ(output.protos().http().client_status_codes().size(), 3);
	EXPECT_EQ(output.protos().http().client_status_codes()[0].status_code(), 7);
	EXPECT_EQ(output.protos().http().client_status_codes()[1].status_code(), 8);
	EXPECT_EQ(output.protos().http().client_status_codes()[2].status_code(), 12);
}

TEST(aggregator, url_details)
{
	draiosproto::metrics input;
	draiosproto::metrics output;

	// url_details is only used in http_info, which tests both appearances of this
	// struct, so there isn't more work to do other than verifying the primary key
	draiosproto::url_details lhs;
	draiosproto::url_details rhs;

	rhs.set_url("1");
	EXPECT_FALSE(url_details_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_url("");

	rhs.mutable_counters()->set_ncalls(1);
	EXPECT_TRUE(url_details_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(url_details_message_aggregator::hasher()(&lhs),
	          url_details_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, counter_proto_entry)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_http()->add_server_urls()->mutable_counters();

	in->set_ncalls(1);
	in->set_time_tot(2);
	in->set_time_max(3);
	in->set_bytes_in(4);
	in->set_bytes_out(5);
	in->set_nerrors(6);
	auto percentile = in->add_percentile();
	percentile->set_percentile(0);
	percentile = in->add_percentile();
	percentile->set_percentile(1);

	// check all places containing counter_proto_entry (a lot)
	input.mutable_protos()->mutable_http()->add_client_urls()->mutable_counters()->set_ncalls(7);
	input.mutable_protos()->mutable_http()->mutable_server_totals()->set_ncalls(8);
	input.mutable_protos()->mutable_http()->mutable_client_totals()->set_ncalls(9);
	input.mutable_protos()->mutable_mysql()->add_server_queries()->mutable_counters()->set_ncalls(
	    10);
	input.mutable_protos()
	    ->mutable_mysql()
	    ->add_server_query_types()
	    ->mutable_counters()
	    ->set_ncalls(11);
	input.mutable_protos()->mutable_mysql()->mutable_server_totals()->set_ncalls(12);
	input.mutable_protos()->mutable_mysql()->mutable_client_totals()->set_ncalls(13);
	input.mutable_protos()->mutable_mongodb()->add_servers_ops()->mutable_counters()->set_ncalls(
	    14);
	input.mutable_protos()
	    ->mutable_mongodb()
	    ->add_server_collections()
	    ->mutable_counters()
	    ->set_ncalls(15);
	input.mutable_protos()->mutable_mongodb()->mutable_server_totals()->set_ncalls(16);
	input.mutable_protos()->mutable_mongodb()->mutable_client_totals()->set_ncalls(17);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_ncalls().sum(), 1);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_bytes_in().sum(), 4);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_bytes_out().sum(), 5);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_nerrors().sum(), 6);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile().size(), 2);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile()[0].percentile(), 0);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile()[1].percentile(), 1);
	EXPECT_EQ(output.protos().http().client_urls()[0].counters().aggr_ncalls().sum(), 7);
	EXPECT_EQ(output.protos().http().server_totals().aggr_ncalls().sum(), 8);
	EXPECT_EQ(output.protos().http().client_totals().aggr_ncalls().sum(), 9);
	EXPECT_EQ(output.protos().mysql().server_queries()[0].counters().aggr_ncalls().sum(), 10);
	EXPECT_EQ(output.protos().mysql().server_query_types()[0].counters().aggr_ncalls().sum(), 11);
	EXPECT_EQ(output.protos().mysql().server_totals().aggr_ncalls().sum(), 12);
	EXPECT_EQ(output.protos().mysql().client_totals().aggr_ncalls().sum(), 13);
	EXPECT_EQ(output.protos().mongodb().servers_ops()[0].counters().aggr_ncalls().sum(), 14);
	EXPECT_EQ(output.protos().mongodb().server_collections()[0].counters().aggr_ncalls().sum(), 15);
	EXPECT_EQ(output.protos().mongodb().server_totals().aggr_ncalls().sum(), 16);
	EXPECT_EQ(output.protos().mongodb().client_totals().aggr_ncalls().sum(), 17);

	in->set_ncalls(100);
	in->set_time_tot(100);
	in->set_time_max(100);
	in->set_bytes_in(100);
	in->set_bytes_out(100);
	in->set_nerrors(100);
	(*in->mutable_percentile())[1].set_percentile(2);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_ncalls().sum(), 101);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_time_tot().sum(), 102);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_time_max().sum(), 103);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_bytes_in().sum(), 104);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_bytes_out().sum(), 105);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().aggr_nerrors().sum(), 106);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile().size(), 3);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile()[0].percentile(), 0);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile()[1].percentile(), 1);
	EXPECT_EQ(output.protos().http().server_urls()[0].counters().percentile()[2].percentile(), 2);
}

TEST(aggregator, status_code_details)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_http()->add_client_status_codes();

	in->set_status_code(1);
	in->set_ncalls(2);
	input.mutable_protos()->mutable_http()->add_server_status_codes()->set_status_code(3);
	auto input2 = input;
	aggregator->aggregate(input2, output, false);

	EXPECT_EQ(output.protos().http().client_status_codes()[0].status_code(), 1);
	EXPECT_EQ(output.protos().http().client_status_codes()[0].aggr_ncalls().sum(), 2);
	EXPECT_EQ(output.protos().http().server_status_codes()[0].status_code(), 3);

	in->set_ncalls(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().http().client_status_codes()[0].aggr_ncalls().sum(), 102);

	// primary key
	draiosproto::status_code_details lhs;
	draiosproto::status_code_details rhs;

	rhs.set_status_code(1);
	EXPECT_FALSE(status_code_details_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_status_code(0);

	rhs.set_ncalls(1);
	EXPECT_TRUE(status_code_details_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(status_code_details_message_aggregator::hasher()(&lhs),
	          status_code_details_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, sql_info)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.mutable_protos()->mutable_mysql()->add_server_queries()->set_name("1");
	input.mutable_protos()->mutable_mysql()->add_server_queries()->set_name("2");
	input.mutable_protos()->mutable_mysql()->add_client_queries()->set_name("3");
	input.mutable_protos()->mutable_mysql()->add_client_queries()->set_name("4");
	input.mutable_protos()->mutable_mysql()->add_server_query_types()->set_type(
	    (draiosproto::sql_statement_type)5);
	input.mutable_protos()->mutable_mysql()->add_server_query_types()->set_type(
	    (draiosproto::sql_statement_type)6);
	input.mutable_protos()->mutable_mysql()->add_client_query_types()->set_type(
	    (draiosproto::sql_statement_type)7);
	input.mutable_protos()->mutable_mysql()->add_client_query_types()->set_type(
	    (draiosproto::sql_statement_type)8);
	input.mutable_protos()->mutable_mysql()->add_server_tables()->set_name("9");
	input.mutable_protos()->mutable_mysql()->add_server_tables()->set_name("10");
	input.mutable_protos()->mutable_mysql()->add_client_tables()->set_name("11");
	input.mutable_protos()->mutable_mysql()->add_client_tables()->set_name("12");
	input.mutable_protos()->mutable_postgres()->add_server_queries()->set_name("13");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().mysql().server_queries().size(), 2);
	EXPECT_EQ(output.protos().mysql().server_queries()[0].name(), "1");
	EXPECT_EQ(output.protos().mysql().server_queries()[1].name(), "2");
	EXPECT_EQ(output.protos().mysql().client_queries().size(), 2);
	EXPECT_EQ(output.protos().mysql().client_queries()[0].name(), "3");
	EXPECT_EQ(output.protos().mysql().client_queries()[1].name(), "4");
	EXPECT_EQ(output.protos().mysql().server_query_types().size(), 2);
	EXPECT_EQ(output.protos().mysql().server_query_types()[0].type(), 5);
	EXPECT_EQ(output.protos().mysql().server_query_types()[1].type(), 6);
	EXPECT_EQ(output.protos().mysql().client_query_types().size(), 2);
	EXPECT_EQ(output.protos().mysql().client_query_types()[0].type(), 7);
	EXPECT_EQ(output.protos().mysql().client_query_types()[1].type(), 8);
	EXPECT_EQ(output.protos().mysql().server_tables().size(), 2);
	EXPECT_EQ(output.protos().mysql().server_tables()[0].name(), "9");
	EXPECT_EQ(output.protos().mysql().server_tables()[1].name(), "10");
	EXPECT_EQ(output.protos().mysql().client_tables().size(), 2);
	EXPECT_EQ(output.protos().mysql().client_tables()[0].name(), "11");
	EXPECT_EQ(output.protos().mysql().client_tables()[1].name(), "12");
	EXPECT_EQ(output.protos().postgres().server_queries()[0].name(), "13");

	(*input.mutable_protos()->mutable_mysql()->mutable_server_queries())[1].set_name("14");
	(*input.mutable_protos()->mutable_mysql()->mutable_client_queries())[1].set_name("15");
	(*input.mutable_protos()->mutable_mysql()->mutable_server_query_types())[1].set_type(
	    (draiosproto::sql_statement_type)7);
	(*input.mutable_protos()->mutable_mysql()->mutable_client_query_types())[1].set_type(
	    (draiosproto::sql_statement_type)9);
	(*input.mutable_protos()->mutable_mysql()->mutable_server_tables())[1].set_name("18");
	(*input.mutable_protos()->mutable_mysql()->mutable_client_tables())[1].set_name("19");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().mysql().server_queries().size(), 3);
	EXPECT_EQ(output.protos().mysql().server_queries()[0].name(), "1");
	EXPECT_EQ(output.protos().mysql().server_queries()[1].name(), "2");
	EXPECT_EQ(output.protos().mysql().server_queries()[2].name(), "14");
	EXPECT_EQ(output.protos().mysql().client_queries().size(), 3);
	EXPECT_EQ(output.protos().mysql().client_queries()[0].name(), "3");
	EXPECT_EQ(output.protos().mysql().client_queries()[1].name(), "4");
	EXPECT_EQ(output.protos().mysql().client_queries()[2].name(), "15");
	EXPECT_EQ(output.protos().mysql().server_query_types().size(), 3);
	EXPECT_EQ(output.protos().mysql().server_query_types()[0].type(), 5);
	EXPECT_EQ(output.protos().mysql().server_query_types()[1].type(), 6);
	EXPECT_EQ(output.protos().mysql().server_query_types()[2].type(), 7);
	EXPECT_EQ(output.protos().mysql().client_query_types().size(), 3);
	EXPECT_EQ(output.protos().mysql().client_query_types()[0].type(), 7);
	EXPECT_EQ(output.protos().mysql().client_query_types()[1].type(), 8);
	EXPECT_EQ(output.protos().mysql().client_query_types()[2].type(), 9);
	EXPECT_EQ(output.protos().mysql().server_tables().size(), 3);
	EXPECT_EQ(output.protos().mysql().server_tables()[0].name(), "9");
	EXPECT_EQ(output.protos().mysql().server_tables()[1].name(), "10");
	EXPECT_EQ(output.protos().mysql().server_tables()[2].name(), "18");
	EXPECT_EQ(output.protos().mysql().client_tables().size(), 3);
	EXPECT_EQ(output.protos().mysql().client_tables()[0].name(), "11");
	EXPECT_EQ(output.protos().mysql().client_tables()[1].name(), "12");
	EXPECT_EQ(output.protos().mysql().client_tables()[2].name(), "19");
}

TEST(aggregator, sql_entry_details)
{
	// sql_entry_details is only used in sql_info, which tests both appearances of this
	// struct, so there isn't more work to do other than verifying the primary key
	draiosproto::sql_entry_details lhs;
	draiosproto::sql_entry_details rhs;

	rhs.set_name("1");
	EXPECT_FALSE(sql_entry_details_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");

	rhs.mutable_counters()->set_ncalls(1);
	EXPECT_TRUE(sql_entry_details_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(sql_entry_details_message_aggregator::hasher()(&lhs),
	          sql_entry_details_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, sql_query_type_details)
{
	// sql_query_type_details is only used in sql_info, which tests both appearances of
	// this struct, so there isn't more work to do other than verifying the primary key
	draiosproto::sql_query_type_details lhs;
	draiosproto::sql_query_type_details rhs;

	rhs.set_type((draiosproto::sql_statement_type)1);
	EXPECT_FALSE(sql_query_type_details_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_type((draiosproto::sql_statement_type)0);

	rhs.mutable_counters()->set_ncalls(1);
	EXPECT_TRUE(sql_query_type_details_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(sql_query_type_details_message_aggregator::hasher()(&lhs),
	          sql_query_type_details_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mongodb_info)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.mutable_protos()->mutable_mongodb()->add_servers_ops()->set_op(
	    (draiosproto::mongodb_op_type)1);
	input.mutable_protos()->mutable_mongodb()->add_servers_ops()->set_op(
	    (draiosproto::mongodb_op_type)2);
	input.mutable_protos()->mutable_mongodb()->add_client_ops()->set_op(
	    (draiosproto::mongodb_op_type)3);
	input.mutable_protos()->mutable_mongodb()->add_client_ops()->set_op(
	    (draiosproto::mongodb_op_type)4);
	input.mutable_protos()->mutable_mongodb()->add_server_collections()->set_name("5");
	input.mutable_protos()->mutable_mongodb()->add_server_collections()->set_name("6");
	input.mutable_protos()->mutable_mongodb()->add_client_collections()->set_name("7");
	input.mutable_protos()->mutable_mongodb()->add_client_collections()->set_name("8");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().mongodb().servers_ops().size(), 2);
	EXPECT_EQ(output.protos().mongodb().servers_ops()[0].op(), 1);
	EXPECT_EQ(output.protos().mongodb().servers_ops()[1].op(), 2);
	EXPECT_EQ(output.protos().mongodb().client_ops().size(), 2);
	EXPECT_EQ(output.protos().mongodb().client_ops()[0].op(), 3);
	EXPECT_EQ(output.protos().mongodb().client_ops()[1].op(), 4);
	EXPECT_EQ(output.protos().mongodb().server_collections().size(), 2);
	EXPECT_EQ(output.protos().mongodb().server_collections()[0].name(), "5");
	EXPECT_EQ(output.protos().mongodb().server_collections()[1].name(), "6");
	EXPECT_EQ(output.protos().mongodb().client_collections().size(), 2);
	EXPECT_EQ(output.protos().mongodb().client_collections()[0].name(), "7");
	EXPECT_EQ(output.protos().mongodb().client_collections()[1].name(), "8");

	(*input.mutable_protos()->mutable_mongodb()->mutable_servers_ops())[1].set_op(
	    (draiosproto::mongodb_op_type)13);
	(*input.mutable_protos()->mutable_mongodb()->mutable_client_ops())[1].set_op(
	    (draiosproto::mongodb_op_type)14);
	(*input.mutable_protos()->mutable_mongodb()->mutable_server_collections())[1].set_name("16");
	(*input.mutable_protos()->mutable_mongodb()->mutable_client_collections())[1].set_name("17");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().mongodb().servers_ops().size(), 3);
	EXPECT_EQ(output.protos().mongodb().servers_ops()[0].op(), 1);
	EXPECT_EQ(output.protos().mongodb().servers_ops()[1].op(), 2);
	EXPECT_EQ(output.protos().mongodb().servers_ops()[2].op(), 13);
	EXPECT_EQ(output.protos().mongodb().client_ops().size(), 3);
	EXPECT_EQ(output.protos().mongodb().client_ops()[0].op(), 3);
	EXPECT_EQ(output.protos().mongodb().client_ops()[1].op(), 4);
	EXPECT_EQ(output.protos().mongodb().client_ops()[2].op(), 14);
	EXPECT_EQ(output.protos().mongodb().server_collections().size(), 3);
	EXPECT_EQ(output.protos().mongodb().server_collections()[0].name(), "5");
	EXPECT_EQ(output.protos().mongodb().server_collections()[1].name(), "6");
	EXPECT_EQ(output.protos().mongodb().server_collections()[2].name(), "16");
	EXPECT_EQ(output.protos().mongodb().client_collections().size(), 3);
	EXPECT_EQ(output.protos().mongodb().client_collections()[0].name(), "7");
	EXPECT_EQ(output.protos().mongodb().client_collections()[1].name(), "8");
	EXPECT_EQ(output.protos().mongodb().client_collections()[2].name(), "17");
}

TEST(aggregator, mongodb_op_type_details)
{
	// mongodb_op_type_details is only used in sql_info, which tests both appearances of
	// this struct, so there isn't more work to do other than verifying the primary key
	draiosproto::mongodb_op_type_details lhs;
	draiosproto::mongodb_op_type_details rhs;

	rhs.set_op((draiosproto::mongodb_op_type)1);
	EXPECT_FALSE(mongodb_op_type_details_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_op((draiosproto::mongodb_op_type)0);

	rhs.mutable_counters()->set_ncalls(1);
	EXPECT_TRUE(mongodb_op_type_details_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mongodb_op_type_details_message_aggregator::hasher()(&lhs),
	          mongodb_op_type_details_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mongodb_collection_details)
{
	// mongdob_collection_details is only used in sql_info, which tests both appearances of this
	// struct, so there isn't more work to do other than verifying the primary key
	draiosproto::mongodb_collection_details lhs;
	draiosproto::mongodb_collection_details rhs;

	rhs.set_name("1");
	EXPECT_FALSE(mongodb_collection_details_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");

	rhs.mutable_counters()->set_ncalls(1);
	EXPECT_TRUE(mongodb_collection_details_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mongodb_collection_details_message_aggregator::hasher()(&lhs),
	          mongodb_collection_details_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, java_info)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.mutable_protos()->mutable_java()->set_process_name("1");
	input.mutable_protos()->mutable_java()->add_beans()->set_name("2");
	input.mutable_protos()->mutable_java()->add_beans()->set_name("3");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().process_name(), "1");
	EXPECT_EQ(output.protos().java().beans().size(), 2);
	EXPECT_EQ(output.protos().java().beans()[0].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[1].name(), "3");

	(*input.mutable_protos()->mutable_java()->mutable_beans())[1].set_name("4");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().java().beans().size(), 3);
	EXPECT_EQ(output.protos().java().beans()[0].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[1].name(), "3");
	EXPECT_EQ(output.protos().java().beans()[2].name(), "4");
}

TEST(aggregator, jmx_bean)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto bean = input.mutable_protos()->mutable_java()->add_beans();
	bean->set_name("1");
	bean->add_attributes()->set_name("2");
	bean->add_attributes()->set_name("3");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].name(), "1");
	EXPECT_EQ(output.protos().java().beans()[0].attributes().size(), 2);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[1].name(), "3");

	(*bean->mutable_attributes())[1].set_name("4");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].attributes().size(), 3);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[1].name(), "3");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[2].name(), "4");

	// validate primary key
	draiosproto::jmx_bean lhs;
	draiosproto::jmx_bean rhs;

	rhs.set_name("1");
	EXPECT_FALSE(jmx_bean_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");

	rhs.add_attributes()->set_name("1");
	EXPECT_TRUE(jmx_bean_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(jmx_bean_message_aggregator::hasher()(&lhs),
	          jmx_bean_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, jmx_attribute)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_java()->add_beans()->add_attributes();
	in->set_name("1");
	in->set_value(2);
	in->add_subattributes()->set_name("1");
	in->add_subattributes()->set_name("2");
	in->set_alias("3");
	in->set_type((draiosproto::jmx_metric_type)2);
	in->set_unit((draiosproto::unit)3);
	in->set_scale((draiosproto::scale)6);
	// SMAGENT-1935

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].name(), "1");
	// subattribute tramples attribute value
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].aggr_value_double().sum(), 0);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes().size(), 2);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes()[0].name(), "1");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes()[1].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].alias(), "3");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].type(), 2);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].unit(), 3);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].scale(), 6);

	(*in->mutable_subattributes())[1].set_name("3");
	in->set_value(100);
	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].aggr_value_double().sum(), 0);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes().size(), 3);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes()[0].name(), "1");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes()[1].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[0].subattributes()[2].name(), "3");

	// check that if we start with a value, then add a subattribute, it quashes the value
	in = input.mutable_protos()->mutable_java()->add_beans()->add_attributes();
	in->set_name("2");
	in->set_value(2);
	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[1].name(), "2");
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[1].aggr_value_double().sum(), 2);
	in->set_value(3);
	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[1].aggr_value_double().sum(), 5);
	// now add a sub-attribute and watch value go bye-bye
	in->add_subattributes()->set_name("1");
	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().java().beans()[0].attributes()[1].aggr_value_double().sum(), 0);

	// validate primary key
	draiosproto::jmx_attribute lhs;
	draiosproto::jmx_attribute rhs;

	rhs.set_name("1");
	EXPECT_FALSE(jmx_attribute_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");

	rhs.set_value(1);
	rhs.add_subattributes();
	rhs.set_alias("1");
	rhs.set_type((draiosproto::jmx_metric_type)1);
	rhs.set_unit((draiosproto::unit)1);
	rhs.set_scale((draiosproto::scale)1);
	rhs.add_segment_by();
	EXPECT_TRUE(jmx_attribute_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(jmx_attribute_message_aggregator::hasher()(&lhs),
	          jmx_attribute_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, statsd_tag)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_internal_metrics()->add_statsd_metrics()->add_tags();
	in->set_key("1");
	in->set_value("2");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].tags()[0].key(), "1");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].tags()[0].value(), "2");

	// validate primary key
	draiosproto::statsd_tag lhs;
	draiosproto::statsd_tag rhs;

	rhs.set_key("1");
	EXPECT_FALSE(statsd_tag_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_key("");

	rhs.set_value("1");
	EXPECT_FALSE(statsd_tag_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_value("");

	EXPECT_TRUE(statsd_tag_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(statsd_tag_message_aggregator::hasher()(&lhs),
	          statsd_tag_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, statsd_info)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.mutable_internal_metrics()->add_statsd_metrics()->set_name("1");
	input.mutable_internal_metrics()->add_statsd_metrics()->set_name("2");
	input.mutable_protos()->mutable_statsd()->add_statsd_metrics()->set_name("3");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.internal_metrics().statsd_metrics().size(), 2);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].name(), "1");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].name(), "2");
	EXPECT_EQ(output.protos().statsd().statsd_metrics().size(), 1);
}

TEST(aggregator, statsd_metric)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_internal_metrics()->add_statsd_metrics();
	in->set_name("1");
	in->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	in->add_tags()->set_key("2");
	in->add_tags()->set_key("3");
	in->set_value(4);
	in->set_sum(5);
	in->set_min(6);
	in->set_max(7);
	in->set_count(8);
	in->set_median(9);
	in->set_percentile_95(10);
	in->set_percentile_99(11);
	in->add_percentile()->set_percentile(0);
	in->add_percentile()->set_percentile(1);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].name(), "1");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].tags().size(), 2);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].tags()[0].key(), "2");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].tags()[1].key(), "3");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].type(), 1);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_value().sum(), 4);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_sum().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_min().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_max().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_count().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_median().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_percentile_95().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_percentile_99().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].percentile().size(), 2);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].percentile()[0].percentile(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].percentile()[1].percentile(), 1);
	in->set_value(100);
	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[0].aggr_value().sum(), 104);

	// test a histogram type
	in->set_name("2");
	in->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].name(), "2");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].tags().size(), 2);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].tags()[0].key(), "2");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].tags()[1].key(), "3");
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].type(), 2);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_value().sum(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_sum().sum(), 5);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_min().sum(), 6);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_max().sum(), 7);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_count().sum(), 8);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_median().sum(), 9);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_percentile_95().sum(), 10);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_percentile_99().sum(), 11);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile().size(), 2);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile()[0].percentile(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile()[1].percentile(), 1);

	in->set_value(100);
	in->set_sum(100);
	in->set_min(100);
	in->set_max(100);
	in->set_count(100);
	in->set_median(100);
	in->set_percentile_95(100);
	in->set_percentile_99(100);
	(*in->mutable_percentile())[0].set_percentile(2);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_sum().sum(), 105);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_min().sum(), 106);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_max().sum(), 107);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_count().sum(), 108);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_median().sum(), 109);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_percentile_95().sum(), 110);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].aggr_percentile_99().sum(), 111);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile().size(), 3);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile()[0].percentile(), 0);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile()[1].percentile(), 1);
	EXPECT_EQ(output.internal_metrics().statsd_metrics()[1].percentile()[2].percentile(), 2);

	// validate primary key
	draiosproto::statsd_metric lhs;
	draiosproto::statsd_metric rhs;

	rhs.set_name("1");
	EXPECT_FALSE(statsd_metric_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");
	rhs.add_tags()->set_key("1");
	EXPECT_FALSE(statsd_metric_message_aggregator::comparer()(&lhs, &rhs));
	lhs.add_tags()->set_key("1");

	rhs.set_type((draiosproto::statsd_metric_type)1);
	rhs.set_value(4);
	rhs.set_sum(5);
	rhs.set_min(6);
	rhs.set_max(7);
	rhs.set_count(8);
	rhs.set_median(9);
	rhs.set_percentile_95(10);
	rhs.set_percentile_99(11);
	rhs.add_percentile()->set_percentile(0);
	rhs.add_percentile()->set_percentile(1);

	EXPECT_TRUE(statsd_metric_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(statsd_metric_message_aggregator::hasher()(&lhs),
	          statsd_metric_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, app_info)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_app();

	in->set_process_name("1");
	in->add_metrics()->set_name("2");
	in->add_metrics()->set_name("3");
	in->add_checks()->set_name("4");
	in->add_checks()->set_name("5");
	input.mutable_protos()->mutable_prometheus()->set_process_name("6");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().app().process_name(), "1");
	EXPECT_EQ(output.protos().app().metrics().size(), 2);
	EXPECT_EQ(output.protos().app().metrics()[0].name(), "2");
	EXPECT_EQ(output.protos().app().metrics()[1].name(), "3");
	EXPECT_EQ(output.protos().app().checks().size(), 2);
	EXPECT_EQ(output.protos().app().checks()[0].name(), "4");
	EXPECT_EQ(output.protos().app().checks()[1].name(), "5");
	EXPECT_EQ(output.protos().prometheus().process_name(), "6");

	(*in->mutable_metrics())[1].set_name("7");
	(*in->mutable_checks())[1].set_name("8");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().app().metrics().size(), 3);
	EXPECT_EQ(output.protos().app().metrics()[0].name(), "2");
	EXPECT_EQ(output.protos().app().metrics()[1].name(), "3");
	EXPECT_EQ(output.protos().app().metrics()[2].name(), "7");
	EXPECT_EQ(output.protos().app().checks().size(), 3);
	EXPECT_EQ(output.protos().app().checks()[0].name(), "4");
	EXPECT_EQ(output.protos().app().checks()[1].name(), "5");
	EXPECT_EQ(output.protos().app().checks()[2].name(), "8");
}

TEST(aggregator, app_metric)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_app()->add_metrics();

	in->set_name("1");
	in->set_type((draiosproto::app_metric_type)2);
	in->set_value(3.5);
	in->add_tags()->set_key("4");
	in->add_tags()->set_key("5");
	in->set_prometheus_type((draiosproto::prometheus_type)1);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().app().metrics()[0].name(), "1");
	EXPECT_EQ(output.protos().app().metrics()[0].type(), 2);
	EXPECT_EQ(output.protos().app().metrics()[0].aggr_value_double().sum(), 3.5);
	EXPECT_EQ(output.protos().app().metrics()[0].tags().size(), 2);
	EXPECT_EQ(output.protos().app().metrics()[0].tags()[0].key(), "4");
	EXPECT_EQ(output.protos().app().metrics()[0].tags()[1].key(), "5");
	EXPECT_EQ(output.protos().app().metrics()[0].prometheus_type(), 1);

	in->set_value(100);
	// can't actaully check adding a tag with a new key, as that results in the metric
	// aggregating to a new message (correctly)

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().app().metrics()[0].aggr_value_double().sum(), 103.5);

	// validate primary key
	draiosproto::app_metric lhs;
	draiosproto::app_metric rhs;

	rhs.set_name("1");
	EXPECT_FALSE(app_metric_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");
	EXPECT_TRUE(app_metric_message_aggregator::comparer()(&lhs, &rhs));

	// Validate keys
	rhs.add_tags()->set_key("1");
	EXPECT_FALSE(app_metric_message_aggregator::comparer()(&lhs, &rhs));
	lhs.add_tags()->set_key("1");
	EXPECT_TRUE(app_metric_message_aggregator::comparer()(&lhs, &rhs));

	auto lhs_tag = lhs.add_tags();
	auto rhs_tag = rhs.add_tags();
	lhs_tag->set_key("5");
	lhs_tag->set_value("6");
	rhs_tag->set_key("5");
	rhs_tag->set_value("7");

	EXPECT_FALSE(app_metric_message_aggregator::comparer()(&lhs, &rhs));
	rhs_tag->set_value("6");
	EXPECT_TRUE(app_metric_message_aggregator::comparer()(&lhs, &rhs));

	rhs.set_type((draiosproto::app_metric_type)1);
	rhs.set_value(4);
	rhs.set_prometheus_type((draiosproto::prometheus_type)1);

	EXPECT_TRUE(app_metric_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(app_metric_message_aggregator::hasher()(&lhs),
	          app_metric_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, app_tag)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_app()->add_metrics()->add_tags();
	in->set_key("1");
	in->set_value("2");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().app().metrics()[0].tags()[0].key(), "1");
	EXPECT_EQ(output.protos().app().metrics()[0].tags()[0].value(), "2");

	// validate primary key
	draiosproto::app_tag lhs;
	draiosproto::app_tag rhs;

	rhs.set_key("1");
	EXPECT_FALSE(app_tag_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_key("");

	// validate that the value is also included in the message (SMAGENT-2624)
	rhs.set_value("4");
	EXPECT_FALSE(app_tag_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_NE(app_tag_message_aggregator::hasher()(&lhs),
	          app_tag_message_aggregator::hasher()(&rhs));
	lhs.set_value("4");
	EXPECT_TRUE(app_tag_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(app_tag_message_aggregator::hasher()(&lhs),
	          app_tag_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, prometheus_info)
{
	test_helpers::scoped_config<bool> enable_prom_agg("aggregate_prometheus", true);
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_prom_info();

	// first check if we do simple aggregations correctly
	in->set_process_name("1");
	in->add_metrics()->set_name("2");
	in->add_metrics()->set_name("3");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().prom_info().process_name(), "1");
	EXPECT_EQ(output.protos().prom_info().metrics().size(), 2);
	EXPECT_EQ(output.protos().prom_info().metrics()[0].name(), "2");
	EXPECT_EQ(output.protos().prom_info().metrics()[1].name(), "3");

	(*in->mutable_metrics())[1].set_name("7");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().prom_info().metrics().size(), 3);
	EXPECT_EQ(output.protos().prom_info().metrics()[0].name(), "2");
	EXPECT_EQ(output.protos().prom_info().metrics()[1].name(), "3");
	EXPECT_EQ(output.protos().prom_info().metrics()[2].name(), "7");
}

TEST(aggregator, app_metric_bucket)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::app_metric_bucket>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::app_metric_bucket>>(
	        &builder.build_app_metric_bucket());

	draiosproto::app_metric_bucket input;
	draiosproto::app_metric_bucket output;

	input.set_label("some label");
	input.set_count(1);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.label(), "some label");
	EXPECT_EQ(output.aggr_count().sum(), 1);

	input.set_count(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.aggr_count().sum(), 101);

	// validate primary key
	draiosproto::app_metric_bucket lhs;
	draiosproto::app_metric_bucket rhs;

	rhs.set_label("1");
	EXPECT_FALSE(app_metric_bucket_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_label("");

	rhs.set_count(4);
	EXPECT_TRUE(app_metric_bucket_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(app_metric_bucket_message_aggregator::hasher()(&lhs),
	          app_metric_bucket_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, app_check)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_protos()->mutable_app()->add_checks();

	in->set_name("1");
	in->set_value((draiosproto::app_check_value)2);
	in->add_tags()->set_key("3");
	in->add_tags()->set_key("4");
	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.protos().app().checks()[0].name(), "1");
	EXPECT_EQ(output.protos().app().checks()[0].value(), 2);
	EXPECT_EQ(output.protos().app().checks()[0].tags().size(), 2);
	EXPECT_EQ(output.protos().app().checks()[0].tags()[0].key(), "3");
	EXPECT_EQ(output.protos().app().checks()[0].tags()[1].key(), "4");

	(*in->mutable_tags())[0].set_key("5");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.protos().app().checks()[0].tags().size(), 3);
	EXPECT_EQ(output.protos().app().checks()[0].tags()[0].key(), "3");
	EXPECT_EQ(output.protos().app().checks()[0].tags()[1].key(), "4");
	EXPECT_EQ(output.protos().app().checks()[0].tags()[2].key(), "5");

	// validate primary key
	draiosproto::app_check lhs;
	draiosproto::app_check rhs;

	rhs.set_name("1");
	EXPECT_FALSE(app_check_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");

	rhs.set_value((draiosproto::app_check_value)2);
	rhs.add_tags();
	EXPECT_TRUE(app_check_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(app_check_message_aggregator::hasher()(&lhs),
	          app_check_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, file_stat)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_top_files();

	in->set_name("1");
	in->set_bytes(2);
	in->set_time_ns(3);
	in->set_open_count(4);
	in->set_errors(5);
	in->set_bytes_in(6);
	in->set_bytes_out(7);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.top_files()[0].name(), "1");
	EXPECT_EQ(output.top_files()[0].aggr_bytes().sum(), 2);
	EXPECT_EQ(output.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(output.top_files()[0].aggr_open_count().sum(), 4);
	EXPECT_EQ(output.top_files()[0].aggr_errors().sum(), 5);
	EXPECT_EQ(output.top_files()[0].aggr_bytes_in().sum(), 6);
	EXPECT_EQ(output.top_files()[0].aggr_bytes_out().sum(), 7);

	in->set_bytes(100);
	in->set_time_ns(100);
	in->set_open_count(100);
	in->set_errors(100);
	in->set_bytes_in(100);
	in->set_bytes_out(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.top_files()[0].aggr_bytes().sum(), 102);
	EXPECT_EQ(output.top_files()[0].aggr_time_ns().sum(), 103);
	EXPECT_EQ(output.top_files()[0].aggr_open_count().sum(), 104);
	EXPECT_EQ(output.top_files()[0].aggr_errors().sum(), 105);
	EXPECT_EQ(output.top_files()[0].aggr_bytes_in().sum(), 106);
	EXPECT_EQ(output.top_files()[0].aggr_bytes_out().sum(), 107);

	// validate primary key
	draiosproto::file_stat lhs;
	draiosproto::file_stat rhs;

	rhs.set_name("1");
	EXPECT_FALSE(file_stat_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_name("");

	rhs.set_bytes(2);
	rhs.set_time_ns(3);
	rhs.set_open_count(4);
	rhs.set_errors(5);
	rhs.set_bytes_in(6);
	rhs.set_bytes_out(7);
	EXPECT_TRUE(file_stat_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(file_stat_message_aggregator::hasher()(&lhs),
	          file_stat_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mounted_fs)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_mounts();

	in->set_device("1");
	in->set_mount_dir("2");
	in->set_type("3");
	in->set_size_bytes(4);
	in->set_used_bytes(5);
	in->set_available_bytes(6);
	in->set_total_inodes(7);
	in->set_used_inodes(8);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.mounts()[0].device(), "1");
	EXPECT_EQ(output.mounts()[0].mount_dir(), "2");
	EXPECT_EQ(output.mounts()[0].type(), "3");
	EXPECT_EQ(output.mounts()[0].aggr_size_bytes().sum(), 4);
	EXPECT_EQ(output.mounts()[0].aggr_used_bytes().sum(), 5);
	EXPECT_EQ(output.mounts()[0].aggr_available_bytes().sum(), 6);
	EXPECT_EQ(output.mounts()[0].aggr_total_inodes().sum(), 7);
	EXPECT_EQ(output.mounts()[0].aggr_used_inodes().sum(), 8);

	in->set_size_bytes(100);
	in->set_used_bytes(100);
	in->set_available_bytes(100);
	in->set_total_inodes(100);
	in->set_used_inodes(100);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mounts()[0].aggr_size_bytes().sum(), 104);
	EXPECT_EQ(output.mounts()[0].aggr_used_bytes().sum(), 105);
	EXPECT_EQ(output.mounts()[0].aggr_available_bytes().sum(), 106);
	EXPECT_EQ(output.mounts()[0].aggr_total_inodes().sum(), 107);
	EXPECT_EQ(output.mounts()[0].aggr_used_inodes().sum(), 108);

	// validate primary key
	draiosproto::mounted_fs lhs;
	draiosproto::mounted_fs rhs;

	rhs.set_mount_dir("1");
	EXPECT_FALSE(mounted_fs_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_mount_dir("");

	rhs.set_device("1");
	rhs.set_type("3");
	rhs.set_size_bytes(4);
	rhs.set_used_bytes(5);
	rhs.set_available_bytes(6);
	rhs.set_total_inodes(7);
	rhs.set_used_inodes(8);

	EXPECT_TRUE(mounted_fs_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mounted_fs_message_aggregator::hasher()(&lhs),
	          mounted_fs_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, container)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_containers();

	in->set_id("1");
	in->set_type((draiosproto::container_type)2);
	in->set_name("3");
	in->set_image("4");
	in->set_transaction_processing_delay(5);
	in->set_next_tiers_delay(6);
	in->add_port_mappings()->set_host_ip(7);
	in->add_port_mappings()->set_host_ip(8);
	in->add_labels()->set_key("9");
	in->add_labels()->set_key("10");
	in->add_mounts()->set_mount_dir("9");
	in->add_mounts()->set_mount_dir("10");
	in->add_network_by_serverports()->set_port(10);
	in->add_network_by_serverports()->set_port(11);
	in->set_mesos_task_id("11");
	in->set_image_id("12");
	in->add_orchestrators_fallback_labels()->set_key("22");
	in->add_orchestrators_fallback_labels()->set_key("23");
	in->set_image_repo("14");
	in->set_image_tag("15");
	in->set_image_digest("16");
	in->add_container_reporting_group_id(17);
	in->add_container_reporting_group_id(18);
	in->add_top_files()->set_name("18");
	in->add_top_files()->set_name("19");
	in->add_top_devices()->set_name("20");
	in->add_top_devices()->set_name("21");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.containers()[0].id(), "1");
	EXPECT_EQ(output.containers()[0].type(), 2);
	EXPECT_EQ(output.containers()[0].name(), "3");
	EXPECT_EQ(output.containers()[0].image(), "4");
	EXPECT_EQ(output.containers()[0].aggr_transaction_processing_delay().sum(), 5);
	EXPECT_EQ(output.containers()[0].aggr_next_tiers_delay().sum(), 6);
	EXPECT_EQ(output.containers()[0].port_mappings().size(), 2);
	EXPECT_EQ(output.containers()[0].port_mappings()[0].host_ip(), 7);
	EXPECT_EQ(output.containers()[0].port_mappings()[1].host_ip(), 8);
	EXPECT_EQ(output.containers()[0].labels().size(), 2);
	EXPECT_EQ(output.containers()[0].labels()[0].key(), "9");
	EXPECT_EQ(output.containers()[0].labels()[1].key(), "10");
	EXPECT_EQ(output.containers()[0].mounts().size(), 2);
	EXPECT_EQ(output.containers()[0].mounts()[0].mount_dir(), "9");
	EXPECT_EQ(output.containers()[0].mounts()[1].mount_dir(), "10");
	EXPECT_EQ(output.containers()[0].network_by_serverports().size(), 2);
	EXPECT_EQ(output.containers()[0].network_by_serverports()[0].port(), 10);
	EXPECT_EQ(output.containers()[0].network_by_serverports()[1].port(), 11);
	EXPECT_EQ(output.containers()[0].mesos_task_id(), "11");
	EXPECT_EQ(output.containers()[0].image_id(), "12");
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels().size(), 2);
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels()[0].key(), "22");
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels()[1].key(), "23");
	EXPECT_EQ(output.containers()[0].image_repo(), "14");
	EXPECT_EQ(output.containers()[0].image_tag(), "15");
	EXPECT_EQ(output.containers()[0].image_digest(), "16");
	EXPECT_EQ(output.containers()[0].container_reporting_group_id().size(), 2);
	EXPECT_EQ(output.containers()[0].container_reporting_group_id()[0], 17);
	EXPECT_EQ(output.containers()[0].container_reporting_group_id()[1], 18);
	EXPECT_EQ(output.containers()[0].top_files().size(), 2);
	EXPECT_EQ(output.containers()[0].top_files()[0].name(), "18");
	EXPECT_EQ(output.containers()[0].top_files()[1].name(), "19");
	EXPECT_EQ(output.containers()[0].top_devices().size(), 2);
	EXPECT_EQ(output.containers()[0].top_devices()[0].name(), "20");
	EXPECT_EQ(output.containers()[0].top_devices()[1].name(), "21");

	in->set_transaction_processing_delay(100);
	in->set_next_tiers_delay(100);
	(*in->mutable_port_mappings())[1].set_host_ip(1);
	(*in->mutable_labels())[1].set_key("1");
	(*in->mutable_orchestrators_fallback_labels())[1].set_key("1");
	(*in->mutable_mounts())[1].set_mount_dir("1");
	(*in->mutable_network_by_serverports())[1].set_port(1);
	(*in->mutable_top_files())[1].set_name("1");
	(*in->mutable_top_devices())[1].set_name("1");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.containers()[0].aggr_transaction_processing_delay().sum(), 105);
	EXPECT_EQ(output.containers()[0].aggr_next_tiers_delay().sum(), 106);
	EXPECT_EQ(output.containers()[0].port_mappings().size(), 3);
	EXPECT_EQ(output.containers()[0].port_mappings()[0].host_ip(), 7);
	EXPECT_EQ(output.containers()[0].port_mappings()[1].host_ip(), 8);
	EXPECT_EQ(output.containers()[0].port_mappings()[2].host_ip(), 1);
	EXPECT_EQ(output.containers()[0].labels().size(), 3);
	EXPECT_EQ(output.containers()[0].labels()[0].key(), "9");
	EXPECT_EQ(output.containers()[0].labels()[1].key(), "10");
	EXPECT_EQ(output.containers()[0].labels()[2].key(), "1");
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels().size(), 3);
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels()[0].key(), "22");
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels()[1].key(), "23");
	EXPECT_EQ(output.containers()[0].orchestrators_fallback_labels()[2].key(), "1");
	EXPECT_EQ(output.containers()[0].mounts().size(), 3);
	EXPECT_EQ(output.containers()[0].mounts()[0].mount_dir(), "9");
	EXPECT_EQ(output.containers()[0].mounts()[1].mount_dir(), "10");
	EXPECT_EQ(output.containers()[0].mounts()[2].mount_dir(), "1");
	EXPECT_EQ(output.containers()[0].network_by_serverports().size(), 3);
	EXPECT_EQ(output.containers()[0].network_by_serverports()[0].port(), 10);
	EXPECT_EQ(output.containers()[0].network_by_serverports()[1].port(), 11);
	EXPECT_EQ(output.containers()[0].network_by_serverports()[2].port(), 1);
	EXPECT_EQ(output.containers()[0].top_files().size(), 3);
	EXPECT_EQ(output.containers()[0].top_files()[0].name(), "18");
	EXPECT_EQ(output.containers()[0].top_files()[1].name(), "19");
	EXPECT_EQ(output.containers()[0].top_files()[2].name(), "1");
	EXPECT_EQ(output.containers()[0].top_devices().size(), 3);
	EXPECT_EQ(output.containers()[0].top_devices()[0].name(), "20");
	EXPECT_EQ(output.containers()[0].top_devices()[1].name(), "21");
	EXPECT_EQ(output.containers()[0].top_devices()[2].name(), "1");

	// validate primary key
	draiosproto::container lhs;
	draiosproto::container rhs;

	rhs.set_id("1");
	EXPECT_FALSE(container_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_id("");

	rhs.set_type((draiosproto::container_type)2);
	rhs.set_name("3");
	rhs.set_image("4");
	rhs.set_transaction_processing_delay(5);
	rhs.set_next_tiers_delay(6);
	rhs.add_port_mappings()->set_host_ip(7);
	rhs.add_labels()->set_key("9");
	rhs.add_orchestrators_fallback_labels()->set_key("21");
	rhs.add_mounts()->set_mount_dir("9");
	rhs.add_network_by_serverports()->set_port(10);
	rhs.set_mesos_task_id("11");
	rhs.set_image_id("12");
	rhs.set_image_repo("14");
	rhs.set_image_tag("15");
	rhs.set_image_digest("16");
	rhs.add_container_reporting_group_id(17);
	rhs.add_top_files()->set_name("18");
	rhs.add_top_devices()->set_name("20");
	EXPECT_TRUE(container_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(container_message_aggregator::hasher()(&lhs),
	          container_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, container_port_mapping)
{
	// validate primary key
	draiosproto::container_port_mapping lhs;
	draiosproto::container_port_mapping rhs;

	rhs.set_host_ip(1);
	EXPECT_FALSE(container_port_mapping_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_host_ip(0);
	rhs.set_host_port(2);
	EXPECT_FALSE(container_port_mapping_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_host_port(0);
	rhs.set_container_ip(3);
	EXPECT_FALSE(container_port_mapping_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_container_ip(0);
	rhs.set_container_port(4);
	EXPECT_FALSE(container_port_mapping_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_container_port(0);

	EXPECT_TRUE(container_port_mapping_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(container_port_mapping_message_aggregator::hasher()(&lhs),
	          container_port_mapping_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, container_label)
{
	// validate primary key
	draiosproto::container_label lhs;
	draiosproto::container_label rhs;

	rhs.set_key("1");
	EXPECT_FALSE(container_label_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_key("");
	rhs.set_value("2");
	EXPECT_FALSE(container_label_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_value("");

	EXPECT_TRUE(container_label_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(container_label_message_aggregator::hasher()(&lhs),
	          container_label_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, command_details)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	input.add_commands()->set_timestamp(1);
	input.add_containers()->add_commands()->set_timestamp(2);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.commands().size(), 1);
	EXPECT_EQ(output.commands()[0].timestamp(), 1);
	EXPECT_EQ(output.containers()[0].commands().size(), 1);
	EXPECT_EQ(output.containers()[0].commands()[0].timestamp(), 2);

	aggregator->aggregate(output, output, false);
	EXPECT_EQ(output.commands().size(), 2);
	EXPECT_EQ(output.containers()[0].commands().size(), 2);
}

TEST(aggregator, k8s_pair)
{
	// validate primary key
	draiosproto::k8s_pair lhs;
	draiosproto::k8s_pair rhs;

	rhs.set_key("1");
	EXPECT_FALSE(k8s_pair_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_key("");

	rhs.set_value("1");
	EXPECT_TRUE(k8s_pair_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_pair_message_aggregator::hasher()(&lhs),
	          k8s_pair_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_common)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_pods()->mutable_common();
	i->set_name("1");
	i->set_uid("2");
	i->set_namespace_("3");
	i->add_labels()->set_key("4");
	i->add_labels()->set_key("5");
	i->add_selectors()->set_key("5");
	i->add_selectors()->set_key("6");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().pods()[0].common().name(), "1");
	EXPECT_EQ(output.kubernetes().pods()[0].common().uid(), "2");
	EXPECT_EQ(output.kubernetes().pods()[0].common().namespace_(), "3");
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels().size(), 2);
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels()[0].key(), "4");
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels()[1].key(), "5");
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors().size(), 2);
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors()[0].key(), "5");
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors()[1].key(), "6");

	i->add_labels()->set_key("7");
	i->add_selectors()->set_key("8");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels().size(), 3);
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels()[0].key(), "4");
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels()[1].key(), "5");
	EXPECT_EQ(output.kubernetes().pods()[0].common().labels()[2].key(), "7");
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors().size(), 3);
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors()[0].key(), "5");
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors()[1].key(), "6");
	EXPECT_EQ(output.kubernetes().pods()[0].common().selectors()[2].key(), "8");

	// validate primary key
	draiosproto::k8s_common lhs;
	draiosproto::k8s_common rhs;

	rhs.set_uid("1");
	EXPECT_FALSE(k8s_common_message_aggregator::comparer()(&lhs, &rhs));
	lhs.set_uid("1");

	rhs.set_name("1");
	rhs.set_namespace_("1");
	rhs.add_labels();
	rhs.add_selectors();
	EXPECT_TRUE(k8s_common_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_common_message_aggregator::hasher()(&lhs),
	          k8s_common_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_namespace)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_namespaces();
	i->set_deployment_count(7);
	i->set_service_count(8);
	i->set_replicaset_count(8);
	i->set_job_count(9);
	i->set_statefulset_count(10);
	i->set_resourcequota_count(11);
	i->set_persistentvolumeclaim_count(12);
	i->set_hpa_count(13);
	i->set_pod_desired_count(14);
	i->set_pod_available_count(15);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_deployment_count().sum(), 7);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_service_count().sum(), 8);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_replicaset_count().sum(), 8);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_job_count().sum(), 9);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_statefulset_count().sum(), 10);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_resourcequota_count().sum(), 11);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_persistentvolumeclaim_count().sum(), 12);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_hpa_count().sum(), 13);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_pod_desired_count().sum(), 14);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_pod_available_count().sum(), 15);

	i->set_deployment_count(100);
	i->set_service_count(100);
	i->set_replicaset_count(100);
	i->set_job_count(100);
	i->set_statefulset_count(100);
	i->set_resourcequota_count(100);
	i->set_persistentvolumeclaim_count(100);
	i->set_hpa_count(100);
	i->set_pod_desired_count(100);
	i->set_pod_available_count(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_deployment_count().sum(), 107);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_service_count().sum(), 108);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_service_count().sum(), 108);

	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_job_count().sum(), 109);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_statefulset_count().sum(), 110);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_resourcequota_count().sum(), 111);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_persistentvolumeclaim_count().sum(), 112);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_hpa_count().sum(), 113);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_pod_desired_count().sum(), 114);
	EXPECT_EQ(output.kubernetes().namespaces()[0].aggr_pod_available_count().sum(), 115);

	// validate primary key
	draiosproto::k8s_namespace lhs;
	draiosproto::k8s_namespace rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_namespace_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_namespace_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_namespace_message_aggregator::hasher()(&lhs),
	          k8s_namespace_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_node)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_nodes();
	i->add_host_ips("1");
	i->add_host_ips("2");
	i->set_capacity_cpu_cores(7);
	i->set_capacity_mem_bytes(8);
	i->set_capacity_pods(9);
	i->set_allocatable_cpu_cores(10);
	i->set_allocatable_mem_bytes(11);
	i->set_allocatable_pods(12);
	i->set_unschedulable(13);
	i->set_ready(14);
	i->set_out_of_disk(15);
	i->set_mem_pressure(16);
	i->set_disk_pressure(17);
	i->set_net_unavailable(18);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().nodes()[0].host_ips().size(), 2);
	EXPECT_EQ(output.kubernetes().nodes()[0].host_ips()[0], "1");
	EXPECT_EQ(output.kubernetes().nodes()[0].host_ips()[1], "2");
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_capacity_cpu_cores().sum(), 7);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_capacity_mem_bytes().sum(), 8);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_capacity_pods().sum(), 9);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_allocatable_cpu_cores().sum(), 10);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_allocatable_mem_bytes().sum(), 11);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_allocatable_pods().sum(), 12);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_unschedulable().sum(), 13);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_ready().sum(), 14);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_out_of_disk().sum(), 15);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_mem_pressure().sum(), 16);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_disk_pressure().sum(), 17);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_net_unavailable().sum(), 18);

	i->clear_host_ips();
	i->add_host_ips("3");
	i->set_capacity_cpu_cores(100);
	i->set_capacity_mem_bytes(100);
	i->set_capacity_pods(100);
	i->set_allocatable_cpu_cores(100);
	i->set_allocatable_mem_bytes(100);
	i->set_allocatable_pods(100);
	i->set_unschedulable(100);
	i->set_ready(100);
	i->set_out_of_disk(100);
	i->set_mem_pressure(100);
	i->set_disk_pressure(100);
	i->set_net_unavailable(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().nodes()[0].host_ips().size(), 1);
	EXPECT_EQ(output.kubernetes().nodes()[0].host_ips()[0], "3");
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_capacity_cpu_cores().sum(), 107);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_capacity_mem_bytes().sum(), 108);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_capacity_pods().sum(), 109);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_allocatable_cpu_cores().sum(), 110);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_allocatable_mem_bytes().sum(), 111);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_allocatable_pods().sum(), 112);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_unschedulable().sum(), 113);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_ready().sum(), 114);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_out_of_disk().sum(), 115);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_mem_pressure().sum(), 116);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_disk_pressure().sum(), 117);
	EXPECT_EQ(output.kubernetes().nodes()[0].aggr_net_unavailable().sum(), 118);

	// validate primary key
	draiosproto::k8s_node lhs;
	draiosproto::k8s_node rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_node_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	rhs.add_host_ips();
	EXPECT_TRUE(k8s_node_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_node_message_aggregator::hasher()(&lhs),
	          k8s_node_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_pod)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_pods();
	i->set_node_name("1");
	i->set_host_ip("2");
	i->set_internal_ip("3");
	i->set_job_name("3");
	i->add_container_ids("4");
	i->add_container_ids("5");
	i->set_restart_count(7);
	i->set_containers_waiting(8);
	i->set_status_ready(9);
	i->set_requests_cpu_cores(10);
	i->set_limits_cpu_cores(11);
	i->set_requests_mem_bytes(12);
	i->set_limits_mem_bytes(13);
	i->set_restart_rate(14);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().pods()[0].node_name(), "1");
	EXPECT_EQ(output.kubernetes().pods()[0].host_ip(), "2");
	EXPECT_EQ(output.kubernetes().pods()[0].internal_ip(), "3");
	EXPECT_EQ(output.kubernetes().pods()[0].job_name(), "3");
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids().size(), 2);
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids()[0], "4");
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids()[1], "5");
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_restart_count().sum(), 7);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_containers_waiting().sum(), 8);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_status_ready().sum(), 9);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_requests_cpu_cores().sum(), 10);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_limits_cpu_cores().sum(), 11);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_requests_mem_bytes().sum(), 12);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_limits_mem_bytes().sum(), 13);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_restart_rate().sum(), 14);

	i->add_container_ids("6");
	i->set_restart_count(100);
	i->set_containers_waiting(100);
	i->set_status_ready(100);
	i->set_requests_cpu_cores(100);
	i->set_limits_cpu_cores(100);
	i->set_requests_mem_bytes(100);
	i->set_limits_mem_bytes(100);
	i->set_restart_rate(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids().size(), 3);
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids()[0], "4");
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids()[1], "5");
	EXPECT_EQ(output.kubernetes().pods()[0].container_ids()[2], "6");
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_restart_count().sum(), 107);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_containers_waiting().sum(), 108);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_status_ready().sum(), 109);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_requests_cpu_cores().sum(), 110);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_limits_cpu_cores().sum(), 111);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_requests_mem_bytes().sum(), 112);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_limits_mem_bytes().sum(), 113);
	EXPECT_EQ(output.kubernetes().pods()[0].aggr_restart_rate().sum(), 114);

	// validate primary key
	draiosproto::k8s_pod lhs;
	draiosproto::k8s_pod rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_pod_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");

	rhs.set_node_name("1");
	rhs.set_host_ip("1");
	rhs.set_internal_ip("1");
	rhs.set_job_name("1");
	rhs.add_container_ids();
	EXPECT_TRUE(k8s_pod_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_pod_message_aggregator::hasher()(&lhs),
	          k8s_pod_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_replication_controller)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_controllers();
	i->set_replicas_desired(7);
	i->set_replicas_running(8);
	i->set_replicas_fully_labeled(9);
	i->set_replicas_ready(10);
	i->set_replicas_available(11);
	i->set_status_replicas(12);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_desired().sum(), 7);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_running().sum(), 8);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_fully_labeled().sum(), 9);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_ready().sum(), 10);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_available().sum(), 11);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_status_replicas().sum(), 12);

	i->set_replicas_desired(100);
	i->set_replicas_running(100);
	i->set_replicas_fully_labeled(100);
	i->set_replicas_ready(100);
	i->set_replicas_available(100);
	i->set_status_replicas(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_desired().sum(), 107);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_running().sum(), 108);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_fully_labeled().sum(), 109);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_ready().sum(), 110);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_replicas_available().sum(), 111);
	EXPECT_EQ(output.kubernetes().controllers()[0].aggr_status_replicas().sum(), 112);

	// validate primary key
	draiosproto::k8s_replication_controller lhs;
	draiosproto::k8s_replication_controller rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_replication_controller_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_replication_controller_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_replication_controller_message_aggregator::hasher()(&lhs),
	          k8s_replication_controller_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_service)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_services();
	i->set_cluster_ip("1");
	i->add_ports()->set_port(1);
	i->add_ports()->set_port(2);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().services()[0].cluster_ip(), "1");
	EXPECT_EQ(output.kubernetes().services()[0].ports().size(), 2);
	EXPECT_EQ(output.kubernetes().services()[0].ports()[0].port(), 1);
	EXPECT_EQ(output.kubernetes().services()[0].ports()[1].port(), 2);

	i->set_cluster_ip("2");
	i->clear_ports();
	i->add_ports()->set_port(3);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().services()[0].cluster_ip(), "1");
	EXPECT_EQ(output.kubernetes().services()[0].ports().size(), 1);
	EXPECT_EQ(output.kubernetes().services()[0].ports()[0].port(), 3);

	// validate primary key
	draiosproto::k8s_service lhs;
	draiosproto::k8s_service rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_service_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_service_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_service_message_aggregator::hasher()(&lhs),
	          k8s_service_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_replica_set)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_replica_sets();
	i->set_replicas_desired(7);
	i->set_replicas_running(8);
	i->set_replicas_fully_labeled(9);
	i->set_replicas_ready(10);
	i->set_replicas_available(11);
	i->set_status_replicas(12);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_desired().sum(), 7);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_running().sum(), 8);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_fully_labeled().sum(), 9);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_ready().sum(), 10);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_available().sum(), 11);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_status_replicas().sum(), 12);

	i->set_replicas_desired(100);
	i->set_replicas_running(100);
	i->set_replicas_fully_labeled(100);
	i->set_replicas_ready(100);
	i->set_replicas_available(100);
	i->set_status_replicas(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_desired().sum(), 107);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_running().sum(), 108);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_fully_labeled().sum(), 109);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_ready().sum(), 110);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_replicas_available().sum(), 111);
	EXPECT_EQ(output.kubernetes().replica_sets()[0].aggr_status_replicas().sum(), 112);

	// validate primary key
	draiosproto::k8s_replica_set lhs;
	draiosproto::k8s_replica_set rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_replica_set_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_replica_set_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_replica_set_message_aggregator::hasher()(&lhs),
	          k8s_replica_set_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_deployment)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_deployments();
	i->set_replicas_desired(7);
	i->set_replicas_running(8);
	i->set_replicas_available(9);
	i->set_replicas_unavailable(10);
	i->set_replicas_updated(11);
	i->set_replicas_paused(12);
	i->set_status_replicas(13);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_desired().sum(), 7);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_running().sum(), 8);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_available().sum(), 9);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_unavailable().sum(), 10);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_updated().sum(), 11);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_paused().sum(), 12);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_status_replicas().sum(), 13);

	i->set_replicas_desired(100);
	i->set_replicas_running(100);
	i->set_replicas_available(100);
	i->set_replicas_unavailable(100);
	i->set_replicas_updated(100);
	i->set_replicas_paused(100);
	i->set_status_replicas(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_desired().sum(), 107);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_running().sum(), 108);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_available().sum(), 109);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_unavailable().sum(), 110);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_updated().sum(), 111);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_paused().sum(), 112);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_status_replicas().sum(), 113);

	// validate primary key
	draiosproto::k8s_deployment lhs;
	draiosproto::k8s_deployment rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_deployment_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_deployment_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_deployment_message_aggregator::hasher()(&lhs),
	          k8s_deployment_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_daemonset)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_daemonsets();
	i->set_current_scheduled(7);
	i->set_desired_scheduled(8);
	i->set_pods_misscheduled(9);
	i->set_pods_ready(10);
	i->set_pods_available(11);
	i->set_pods_unavailable(12);
	i->set_updated_scheduled(13);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_scheduled().sum(), 7);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_desired().sum(), 8);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_misscheduled().sum(), 9);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_ready().sum(), 10);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_available().sum(), 11);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_unavailable().sum(), 12);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_updated().sum(), 13);

	i->set_current_scheduled(100);
	i->set_desired_scheduled(100);
	i->set_pods_misscheduled(100);
	i->set_pods_ready(100);
	i->set_pods_available(100);
	i->set_pods_unavailable(100);
	i->set_updated_scheduled(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_scheduled().sum(), 107);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_desired().sum(), 108);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_misscheduled().sum(), 109);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_ready().sum(), 110);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_available().sum(), 111);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_unavailable().sum(), 112);
	EXPECT_EQ(output.kubernetes().daemonsets()[0].aggr_pods_updated().sum(), 113);

	// validate primary key
	draiosproto::k8s_daemonset lhs;
	draiosproto::k8s_daemonset rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_daemonset_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_daemonset_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_daemonset_message_aggregator::hasher()(&lhs),
	          k8s_daemonset_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_job)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_jobs();
	i->set_parallelism(7);
	i->set_completions(8);
	i->set_status_active(9);
	i->set_num_succeeded(10);
	i->set_num_failed(11);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_parallelism().sum(), 7);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_completions().sum(), 8);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_status_active().sum(), 9);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_num_succeeded().sum(), 10);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_num_failed().sum(), 11);

	i->set_parallelism(100);
	i->set_completions(100);
	i->set_status_active(100);
	i->set_num_succeeded(100);
	i->set_num_failed(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_parallelism().sum(), 107);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_completions().sum(), 108);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_status_active().sum(), 109);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_num_succeeded().sum(), 110);
	EXPECT_EQ(output.kubernetes().jobs()[0].aggr_num_failed().sum(), 111);

	// validate primary key
	draiosproto::k8s_job lhs;
	draiosproto::k8s_job rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_job_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_job_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_job_message_aggregator::hasher()(&lhs),
	          k8s_job_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_statefulset)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_statefulsets();
	i->set_replicas(7);
	i->set_status_replicas(8);
	i->set_status_replicas_current(9);
	i->set_status_replicas_ready(10);
	i->set_status_replicas_updated(11);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_replicas().sum(), 7);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas().sum(), 8);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas_current().sum(), 9);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas_ready().sum(), 10);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas_updated().sum(), 11);

	i->set_replicas(100);
	i->set_status_replicas(100);
	i->set_status_replicas_current(100);
	i->set_status_replicas_ready(100);
	i->set_status_replicas_updated(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_replicas().sum(), 107);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas().sum(), 108);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas_current().sum(), 109);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas_ready().sum(), 110);
	EXPECT_EQ(output.kubernetes().statefulsets()[0].aggr_status_replicas_updated().sum(), 111);

	// validate primary key
	draiosproto::k8s_statefulset lhs;
	draiosproto::k8s_statefulset rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_statefulset_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_statefulset_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_statefulset_message_aggregator::hasher()(&lhs),
	          k8s_statefulset_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_resourcequota)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_resourcequotas();
	i->set_limits_cpu_hard(7);
	i->set_limits_memory_hard(8);
	i->set_requests_cpu_hard(9);
	i->set_requests_memory_hard(10);
	i->set_limits_cpu_used(11);
	i->set_limits_memory_used(12);
	i->set_requests_cpu_used(13);
	i->set_requests_memory_used(14);
	i->set_double_limits_cpu_hard(15);
	i->set_double_request_cpu_hard(16);
	i->set_double_limits_cpu_used(17);
	i->set_double_request_cpu_used(19);
	i->set_requests_storage_hard(20);
	i->set_requests_storage_used(21);
	i->set_configmaps_hard(22);
	i->set_persistentvolumeclaims_hard(23);
	i->set_pods_hard(24);
	i->set_replicationcontrollers_hard(25);
	i->set_resourcequotas_hard(26);
	i->set_services_hard(27);
	i->set_services_loadbalancers_hard(28);
	i->set_services_nodeports_hard(29);
	i->set_secrets_hard(30);
	i->set_configmaps_used(31);
	i->set_persistentvolumeclaims_used(32);
	i->set_pods_used(33);
	i->set_replicationcontrollers_used(34);
	i->set_resourcequotas_used(35);
	i->set_services_used(36);
	i->set_services_loadbalancers_used(37);
	i->set_services_nodeports_used(38);
	i->set_secrets_used(39);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_cpu_hard().sum(), 7);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_memory_hard().sum(), 8);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_cpu_hard().sum(), 9);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_memory_hard().sum(), 10);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_cpu_used().sum(), 11);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_memory_used().sum(), 12);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_cpu_used().sum(), 13);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_memory_used().sum(), 14);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_limits_cpu_hard().sum(), 15);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_request_cpu_hard().sum(), 16);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_limits_cpu_used().sum(), 17);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_request_cpu_used().sum(), 19);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_storage_hard().sum(), 20);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_storage_used().sum(), 21);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_configmaps_hard().sum(), 22);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_persistentvolumeclaims_hard().sum(), 23);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_pods_hard().sum(), 24);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_replicationcontrollers_hard().sum(), 25);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_resourcequotas_hard().sum(), 26);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_hard().sum(), 27);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_loadbalancers_hard().sum(), 28);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_nodeports_hard().sum(), 29);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_secrets_hard().sum(), 30);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_configmaps_used().sum(), 31);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_persistentvolumeclaims_used().sum(), 32);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_pods_used().sum(), 33);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_replicationcontrollers_used().sum(), 34);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_resourcequotas_used().sum(), 35);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_used().sum(), 36);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_loadbalancers_used().sum(), 37);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_nodeports_used().sum(), 38);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_secrets_used().sum(), 39);

	i->set_limits_cpu_hard(100);
	i->set_limits_memory_hard(100);
	i->set_requests_cpu_hard(100);
	i->set_requests_memory_hard(100);
	i->set_limits_cpu_used(100);
	i->set_limits_memory_used(100);
	i->set_requests_cpu_used(100);
	i->set_requests_memory_used(100);
	i->set_double_limits_cpu_hard(100);
	i->set_double_request_cpu_hard(100);
	i->set_double_limits_cpu_used(100);
	i->set_double_request_cpu_used(100);
	i->set_requests_storage_hard(100);
	i->set_requests_storage_used(100);
	i->set_configmaps_hard(100);
	i->set_persistentvolumeclaims_hard(100);
	i->set_pods_hard(100);
	i->set_replicationcontrollers_hard(100);
	i->set_resourcequotas_hard(100);
	i->set_services_hard(100);
	i->set_services_loadbalancers_hard(100);
	i->set_services_nodeports_hard(100);
	i->set_secrets_hard(100);
	i->set_configmaps_used(100);
	i->set_persistentvolumeclaims_used(100);
	i->set_pods_used(100);
	i->set_replicationcontrollers_used(100);
	i->set_resourcequotas_used(100);
	i->set_services_used(100);
	i->set_services_loadbalancers_used(100);
	i->set_services_nodeports_used(100);
	i->set_secrets_used(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_cpu_hard().sum(), 107);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_memory_hard().sum(), 108);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_cpu_hard().sum(), 109);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_memory_hard().sum(), 110);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_cpu_used().sum(), 111);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_limits_memory_used().sum(), 112);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_cpu_used().sum(), 113);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_memory_used().sum(), 114);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_limits_cpu_hard().sum(), 115);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_request_cpu_hard().sum(), 116);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_limits_cpu_used().sum(), 117);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_double_request_cpu_used().sum(), 119);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_storage_hard().sum(), 120);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_requests_storage_used().sum(), 121);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_configmaps_hard().sum(), 122);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_persistentvolumeclaims_hard().sum(),
	          123);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_pods_hard().sum(), 124);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_replicationcontrollers_hard().sum(),
	          125);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_resourcequotas_hard().sum(), 126);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_hard().sum(), 127);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_loadbalancers_hard().sum(),
	          128);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_nodeports_hard().sum(), 129);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_secrets_hard().sum(), 130);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_configmaps_used().sum(), 131);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_persistentvolumeclaims_used().sum(),
	          132);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_pods_used().sum(), 133);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_replicationcontrollers_used().sum(),
	          134);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_resourcequotas_used().sum(), 135);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_used().sum(), 136);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_loadbalancers_used().sum(),
	          137);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_services_nodeports_used().sum(), 138);
	EXPECT_EQ(output.kubernetes().resourcequotas()[0].aggr_secrets_used().sum(), 139);

	// validate primary key
	draiosproto::k8s_resourcequota lhs;
	draiosproto::k8s_resourcequota rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_resourcequota_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_resourcequota_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_resourcequota_message_aggregator::hasher()(&lhs),
	          k8s_resourcequota_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_persistentvolume)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_persistentvolumes();
	i->set_storage(7);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().persistentvolumes()[0].aggr_storage().sum(), 7);

	i->set_storage(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().persistentvolumes()[0].aggr_storage().sum(), 107);

	// validate primary key
	draiosproto::k8s_persistentvolume lhs;
	draiosproto::k8s_persistentvolume rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_persistentvolume_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_persistentvolume_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_persistentvolume_message_aggregator::hasher()(&lhs),
	          k8s_persistentvolume_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_persistentvolumeclaim)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_persistentvolumeclaims();
	i->set_storage(7);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().persistentvolumeclaims()[0].aggr_storage().sum(), 7);

	i->set_storage(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().persistentvolumeclaims()[0].aggr_storage().sum(), 107);

	// validate primary key
	draiosproto::k8s_persistentvolumeclaim lhs;
	draiosproto::k8s_persistentvolumeclaim rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_persistentvolumeclaim_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_persistentvolumeclaim_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_persistentvolumeclaim_message_aggregator::hasher()(&lhs),
	          k8s_persistentvolumeclaim_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_hpa)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_hpas();
	i->set_replicas_min(7);
	i->set_replicas_max(8);
	i->set_replicas_current(9);
	i->set_replicas_desired(10);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_min().sum(), 7);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_max().sum(), 8);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_current().sum(), 9);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_desired().sum(), 10);

	i->set_replicas_min(100);
	i->set_replicas_max(100);
	i->set_replicas_current(100);
	i->set_replicas_desired(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_min().sum(), 107);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_max().sum(), 108);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_current().sum(), 109);
	EXPECT_EQ(output.kubernetes().hpas()[0].aggr_replicas_desired().sum(), 110);

	// validate primary key
	draiosproto::k8s_hpa lhs;
	draiosproto::k8s_hpa rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_hpa_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_hpa_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_hpa_message_aggregator::hasher()(&lhs),
	          k8s_hpa_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, k8s_state)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto i = input.mutable_kubernetes()->add_deployments();
	i->set_replicas_desired(7);
	i->set_replicas_running(8);
	i->set_replicas_available(9);
	i->set_replicas_unavailable(10);
	i->set_replicas_updated(11);
	i->set_replicas_paused(12);
	i->set_status_replicas(13);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_desired().sum(), 7);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_running().sum(), 8);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_available().sum(), 9);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_unavailable().sum(), 10);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_updated().sum(), 11);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_paused().sum(), 12);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_status_replicas().sum(), 13);

	i->set_replicas_desired(100);
	i->set_replicas_running(100);
	i->set_replicas_available(100);
	i->set_replicas_unavailable(100);
	i->set_replicas_updated(100);
	i->set_replicas_paused(100);
	i->set_status_replicas(100);
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_desired().sum(), 107);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_running().sum(), 108);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_available().sum(), 109);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_unavailable().sum(), 110);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_updated().sum(), 111);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_replicas_paused().sum(), 112);
	EXPECT_EQ(output.kubernetes().deployments()[0].aggr_status_replicas().sum(), 113);

	// validate primary key
	draiosproto::k8s_deployment lhs;
	draiosproto::k8s_deployment rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(k8s_deployment_message_aggregator::comparer()(&lhs, &rhs));
	lhs.mutable_common()->set_uid("1");
	EXPECT_TRUE(k8s_deployment_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(k8s_deployment_message_aggregator::hasher()(&lhs),
	          k8s_deployment_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mesos_state)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_mesos();

	in->add_frameworks()->mutable_common()->set_uid("1");
	in->add_frameworks()->mutable_common()->set_uid("2");
	in->add_groups()->set_id("3");
	in->add_groups()->set_id("4");
	in->add_slaves()->mutable_common()->set_uid("4");
	in->add_slaves()->mutable_common()->set_uid("5");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.mesos().frameworks().size(), 2);
	EXPECT_EQ(output.mesos().frameworks()[0].common().uid(), "1");
	EXPECT_EQ(output.mesos().frameworks()[1].common().uid(), "2");
	EXPECT_EQ(output.mesos().groups().size(), 2);
	EXPECT_EQ(output.mesos().groups()[0].id(), "3");
	EXPECT_EQ(output.mesos().groups()[1].id(), "4");
	EXPECT_EQ(output.mesos().slaves().size(), 2);
	EXPECT_EQ(output.mesos().slaves()[0].common().uid(), "4");
	EXPECT_EQ(output.mesos().slaves()[1].common().uid(), "5");

	(*in->mutable_frameworks())[1].mutable_common()->set_uid("6");
	(*in->mutable_groups())[1].set_id("7");
	(*in->mutable_slaves())[1].mutable_common()->set_uid("8");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mesos().frameworks().size(), 3);
	EXPECT_EQ(output.mesos().frameworks()[0].common().uid(), "1");
	EXPECT_EQ(output.mesos().frameworks()[1].common().uid(), "2");
	EXPECT_EQ(output.mesos().frameworks()[2].common().uid(), "6");
	EXPECT_EQ(output.mesos().groups().size(), 3);
	EXPECT_EQ(output.mesos().groups()[0].id(), "3");
	EXPECT_EQ(output.mesos().groups()[1].id(), "4");
	EXPECT_EQ(output.mesos().groups()[2].id(), "7");
	EXPECT_EQ(output.mesos().slaves().size(), 3);
	EXPECT_EQ(output.mesos().slaves()[0].common().uid(), "4");
	EXPECT_EQ(output.mesos().slaves()[1].common().uid(), "5");
	EXPECT_EQ(output.mesos().slaves()[2].common().uid(), "8");
}

TEST(aggregator, mesos_framework)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_mesos()->add_frameworks();

	in->add_tasks()->mutable_common()->set_uid("1");
	in->add_tasks()->mutable_common()->set_uid("2");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.mesos().frameworks()[0].tasks().size(), 2);
	EXPECT_EQ(output.mesos().frameworks()[0].tasks()[0].common().uid(), "1");
	EXPECT_EQ(output.mesos().frameworks()[0].tasks()[1].common().uid(), "2");

	(*in->mutable_tasks())[0].mutable_common()->set_uid("3");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mesos().frameworks()[0].tasks().size(), 3);
	EXPECT_EQ(output.mesos().frameworks()[0].tasks()[0].common().uid(), "1");
	EXPECT_EQ(output.mesos().frameworks()[0].tasks()[1].common().uid(), "2");
	EXPECT_EQ(output.mesos().frameworks()[0].tasks()[2].common().uid(), "3");

	// validate primary key
	draiosproto::mesos_framework lhs;
	draiosproto::mesos_framework rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(mesos_framework_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_common()->set_uid("");

	rhs.add_tasks();
	EXPECT_TRUE(mesos_framework_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mesos_framework_message_aggregator::hasher()(&lhs),
	          mesos_framework_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mesos_common)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_mesos()->add_frameworks()->mutable_common();

	in->set_uid("1");
	in->set_name("2");
	in->add_labels()->set_key("3");
	in->add_labels()->set_key("4");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.mesos().frameworks()[0].common().uid(), "1");
	EXPECT_EQ(output.mesos().frameworks()[0].common().name(), "2");
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels().size(), 2);
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels()[0].key(), "3");
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels()[1].key(), "4");

	(*in->mutable_labels())[0].set_key("5");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels().size(), 3);
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels()[0].key(), "3");
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels()[1].key(), "4");
	EXPECT_EQ(output.mesos().frameworks()[0].common().labels()[2].key(), "5");

	// validate primary key
	draiosproto::mesos_common lhs;
	draiosproto::mesos_common rhs;

	rhs.set_uid("1");
	EXPECT_FALSE(mesos_common_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_uid("");

	rhs.set_name("1");
	rhs.add_labels();
	EXPECT_TRUE(mesos_common_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mesos_common_message_aggregator::hasher()(&lhs),
	          mesos_common_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mesos_pair)
{
	// validate primary key
	draiosproto::mesos_pair lhs;
	draiosproto::mesos_pair rhs;

	rhs.set_key("1");
	EXPECT_FALSE(mesos_pair_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_key("");

	rhs.set_value("1");
	EXPECT_TRUE(mesos_pair_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mesos_pair_message_aggregator::hasher()(&lhs),
	          mesos_pair_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mesos_task)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_mesos()->add_frameworks()->add_tasks();

	in->set_slave_id("1");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mesos().frameworks()[0].tasks()[0].slave_id(), "1");

	// validate primary key
	draiosproto::mesos_task lhs;
	draiosproto::mesos_task rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(mesos_task_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_common()->set_uid("");

	rhs.set_slave_id("1");
	EXPECT_TRUE(mesos_task_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mesos_task_message_aggregator::hasher()(&lhs),
	          mesos_task_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, marathon_group)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_mesos()->add_groups();

	in->set_id("1");
	in->add_apps()->set_id("2");
	in->add_apps()->set_id("3");
	in->add_groups()->set_id("4");
	in->add_groups()->set_id("5");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.mesos().groups()[0].id(), "1");
	EXPECT_EQ(output.mesos().groups()[0].apps().size(), 2);
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].id(), "2");
	EXPECT_EQ(output.mesos().groups()[0].apps()[1].id(), "3");
	EXPECT_EQ(output.mesos().groups()[0].groups().size(), 2);
	EXPECT_EQ(output.mesos().groups()[0].groups()[0].id(), "4");
	EXPECT_EQ(output.mesos().groups()[0].groups()[1].id(), "5");

	(*in->mutable_apps())[1].set_id("6");
	(*in->mutable_groups())[1].set_id("7");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mesos().groups()[0].apps().size(), 3);
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].id(), "2");
	EXPECT_EQ(output.mesos().groups()[0].apps()[1].id(), "3");
	EXPECT_EQ(output.mesos().groups()[0].apps()[2].id(), "6");
	EXPECT_EQ(output.mesos().groups()[0].groups().size(), 3);
	EXPECT_EQ(output.mesos().groups()[0].groups()[0].id(), "4");
	EXPECT_EQ(output.mesos().groups()[0].groups()[1].id(), "5");
	EXPECT_EQ(output.mesos().groups()[0].groups()[2].id(), "7");

	// validate primary key
	draiosproto::marathon_group lhs;
	draiosproto::marathon_group rhs;

	rhs.set_id("1");
	EXPECT_FALSE(marathon_group_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_id("");

	rhs.add_apps();
	rhs.add_groups();
	EXPECT_TRUE(marathon_group_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(marathon_group_message_aggregator::hasher()(&lhs),
	          marathon_group_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, marathon_app)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_mesos()->add_groups()->add_apps();

	in->set_id("1");
	in->add_task_ids("2");
	in->add_task_ids("3");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].id(), "1");
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids().size(), 2);
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids()[0], "2");
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids()[1], "3");

	in->add_task_ids("4");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids().size(), 3);
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids()[0], "2");
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids()[1], "3");
	EXPECT_EQ(output.mesos().groups()[0].apps()[0].task_ids()[2], "4");

	// validate primary key
	draiosproto::marathon_app lhs;
	draiosproto::marathon_app rhs;

	rhs.set_id("1");
	EXPECT_FALSE(marathon_app_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_id("");

	rhs.add_task_ids();
	EXPECT_TRUE(marathon_app_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(marathon_app_message_aggregator::hasher()(&lhs),
	          marathon_app_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, mesos_slave)
{
	// validate primary key
	draiosproto::mesos_slave lhs;
	draiosproto::mesos_slave rhs;

	rhs.mutable_common()->set_uid("1");
	EXPECT_FALSE(mesos_slave_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_common()->set_uid("");

	EXPECT_TRUE(mesos_slave_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(mesos_slave_message_aggregator::hasher()(&lhs),
	          mesos_slave_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, agent_event)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_events();

	in->set_timestamp_sec(1);
	in->set_scope("2");
	in->set_title("3");
	in->set_description("4");
	in->set_severity(5);
	in->add_tags()->set_key("1");
	in->add_tags()->set_key("2");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.events()[0].timestamp_sec(), 1);
	EXPECT_EQ(output.events()[0].scope(), "2");
	EXPECT_EQ(output.events()[0].title(), "3");
	EXPECT_EQ(output.events()[0].description(), "4");
	EXPECT_EQ(output.events()[0].severity(), 5);
	EXPECT_EQ(output.events()[0].tags().size(), 2);
	EXPECT_EQ(output.events()[0].tags()[0].key(), "1");
	EXPECT_EQ(output.events()[0].tags()[1].key(), "2");

	(*in->mutable_tags())[1].set_key("3");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.events().size(), 1);
	// tags should have gotten replaced
	EXPECT_EQ(output.events()[0].tags().size(), 2);
	EXPECT_EQ(output.events()[0].tags()[0].key(), "1");
	EXPECT_EQ(output.events()[0].tags()[1].key(), "3");

	// validate primary key
	draiosproto::agent_event lhs;
	draiosproto::agent_event rhs;

	rhs.set_timestamp_sec(1);
	EXPECT_FALSE(agent_event_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_timestamp_sec(0);
	rhs.set_scope("2");
	EXPECT_FALSE(agent_event_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_scope("");
	rhs.set_title("1");
	EXPECT_FALSE(agent_event_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_title("");
	rhs.set_description("1");
	EXPECT_FALSE(agent_event_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_description("");
	rhs.set_severity(1);
	EXPECT_FALSE(agent_event_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_severity(0);

	rhs.add_tags();
	EXPECT_TRUE(agent_event_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(agent_event_message_aggregator::hasher()(&lhs),
	          agent_event_message_aggregator::hasher()(&rhs));
}

// SMAGENT-1935
TEST(aggregator, key_value)
{
	// validate primary key
	draiosproto::key_value lhs;
	draiosproto::key_value rhs;

	rhs.set_key("1");
	EXPECT_FALSE(key_value_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_key("");
	rhs.set_value("1");
	EXPECT_FALSE(key_value_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_value("");

	EXPECT_TRUE(key_value_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(key_value_message_aggregator::hasher()(&lhs),
	          key_value_message_aggregator::hasher()(&rhs));
}

// this is just a deep-copy each time we have data...so check that it works
TEST(aggregator, falco_baseline)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_falcobl();

	// check that containers group correctly
	in->add_containers();
	in->add_containers();

	(*in->mutable_containers())[0].set_id("0");
	(*in->mutable_containers())[1].set_id("1");
	in->add_progs();
	in->add_progs();
	(*in->mutable_progs())[0].set_comm("0");
	(*in->mutable_progs())[1].set_comm("1");
	(*in->mutable_progs())[0].add_cats();
	(*in->mutable_progs())[0].add_cats();

	(*(*in->mutable_progs())[0].mutable_cats())[0].set_name("0");
	(*(*in->mutable_progs())[0].mutable_cats())[1].set_name("1");
	(*(*in->mutable_progs())[0].mutable_cats())[0].add_startup_subcats()->add_subcats();
	(*(*(*in->mutable_progs())[0].mutable_cats())[0].mutable_startup_subcats())[0].add_subcats();
	(*(*(*(*in->mutable_progs())[0].mutable_cats())[0].mutable_startup_subcats())[0]
	      .mutable_subcats())[0]
	    .set_name("0");
	(*(*(*(*in->mutable_progs())[0].mutable_cats())[0].mutable_startup_subcats())[0]
	      .mutable_subcats())[0]
	    .add_d("1");
	(*(*(*(*in->mutable_progs())[0].mutable_cats())[0].mutable_startup_subcats())[0]
	      .mutable_subcats())[0]
	    .add_d("2");
	(*(*(*(*in->mutable_progs())[0].mutable_cats())[0].mutable_startup_subcats())[0]
	      .mutable_subcats())[1]
	    .set_name("1");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.falcobl().containers().size(), 2);
	EXPECT_EQ(output.falcobl().containers()[0].id(), "0");
	EXPECT_EQ(output.falcobl().containers()[1].id(), "1");
	EXPECT_EQ(output.falcobl().progs().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].comm(), "0");
	EXPECT_EQ(output.falcobl().progs()[1].comm(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].name(), "0");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[1].name(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].name(), "0");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[1].name(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d().size(),
	          2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d()[0], "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d()[1], "2");

	// aggregate again just to make sure nothing changes
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.falcobl().containers().size(), 2);
	EXPECT_EQ(output.falcobl().containers()[0].id(), "0");
	EXPECT_EQ(output.falcobl().containers()[1].id(), "1");
	EXPECT_EQ(output.falcobl().progs().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].comm(), "0");
	EXPECT_EQ(output.falcobl().progs()[1].comm(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].name(), "0");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[1].name(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].name(), "0");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[1].name(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d().size(),
	          2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d()[0], "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d()[1], "2");

	// aggregate an empty one to make sure it doesn't change
	draiosproto::metrics empty;
	aggregator->aggregate(empty, output, false);
	EXPECT_EQ(output.falcobl().containers().size(), 2);
	EXPECT_EQ(output.falcobl().containers()[0].id(), "0");
	EXPECT_EQ(output.falcobl().containers()[1].id(), "1");
	EXPECT_EQ(output.falcobl().progs().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].comm(), "0");
	EXPECT_EQ(output.falcobl().progs()[1].comm(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].name(), "0");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[1].name(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats().size(), 2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].name(), "0");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[1].name(), "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d().size(),
	          2);
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d()[0], "1");
	EXPECT_EQ(output.falcobl().progs()[0].cats()[0].startup_subcats()[0].subcats()[0].d()[1], "2");

	// aggregate a different PB to make sure it gets overwritten
	draiosproto::metrics replacement;

	in = replacement.mutable_falcobl();

	// check that containers group correctly
	in->add_containers();
	(*in->mutable_containers())[0].set_id("NEW");
	aggregator->aggregate(replacement, output, false);
	EXPECT_EQ(output.falcobl().containers().size(), 1);
	EXPECT_EQ(output.falcobl().containers()[0].id(), "NEW");
	EXPECT_EQ(output.falcobl().progs().size(), 0);
}

TEST(aggregator, swarm_state)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_swarm();

	in->add_services()->mutable_common()->set_id("1");
	in->add_services()->mutable_common()->set_id("2");
	in->add_nodes()->mutable_common()->set_id("3");
	in->add_nodes()->mutable_common()->set_id("4");
	in->add_tasks()->mutable_common()->set_id("5");
	in->add_tasks()->mutable_common()->set_id("6");
	in->set_quorum(false);
	in->set_node_id("7");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.swarm().services().size(), 2);
	EXPECT_EQ(output.swarm().services()[0].common().id(), "1");
	EXPECT_EQ(output.swarm().services()[1].common().id(), "2");
	EXPECT_EQ(output.swarm().nodes().size(), 2);
	EXPECT_EQ(output.swarm().nodes()[0].common().id(), "3");
	EXPECT_EQ(output.swarm().nodes()[1].common().id(), "4");
	EXPECT_EQ(output.swarm().tasks().size(), 2);
	EXPECT_EQ(output.swarm().tasks()[0].common().id(), "5");
	EXPECT_EQ(output.swarm().tasks()[1].common().id(), "6");
	EXPECT_EQ(output.swarm().aggr_quorum().sum(), 0);
	EXPECT_EQ(output.swarm().node_id(), "7");

	(*in->mutable_services())[1].mutable_common()->set_id("8");
	(*in->mutable_nodes())[1].mutable_common()->set_id("8");
	(*in->mutable_tasks())[1].mutable_common()->set_id("8");
	in->set_quorum(true);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.swarm().services().size(), 3);
	EXPECT_EQ(output.swarm().services()[0].common().id(), "1");
	EXPECT_EQ(output.swarm().services()[1].common().id(), "2");
	EXPECT_EQ(output.swarm().services()[2].common().id(), "8");
	EXPECT_EQ(output.swarm().nodes().size(), 3);
	EXPECT_EQ(output.swarm().nodes()[0].common().id(), "3");
	EXPECT_EQ(output.swarm().nodes()[1].common().id(), "4");
	EXPECT_EQ(output.swarm().nodes()[2].common().id(), "8");
	EXPECT_EQ(output.swarm().tasks().size(), 3);
	EXPECT_EQ(output.swarm().tasks()[0].common().id(), "5");
	EXPECT_EQ(output.swarm().tasks()[1].common().id(), "6");
	EXPECT_EQ(output.swarm().tasks()[2].common().id(), "8");
	EXPECT_EQ(output.swarm().aggr_quorum().sum(), 1);
}

TEST(aggregator, swarm_service)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_swarm()->add_services();
	input.mutable_swarm()->add_nodes();  // swarm needs a node to deliver anything

	in->mutable_common()->set_id("1");
	in->add_virtual_ips("2");
	in->add_virtual_ips("3");
	in->add_ports()->set_port(4);
	in->add_ports()->set_port(5);
	in->set_mode((draiosproto::swarm_service_mode)1);
	in->set_spec_replicas(6);
	in->set_tasks(7);

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.swarm().services()[0].common().id(), "1");
	EXPECT_EQ(output.swarm().services()[0].virtual_ips().size(), 2);
	EXPECT_EQ(output.swarm().services()[0].virtual_ips()[0], "2");
	EXPECT_EQ(output.swarm().services()[0].virtual_ips()[1], "3");
	EXPECT_EQ(output.swarm().services()[0].ports().size(), 2);
	EXPECT_EQ(output.swarm().services()[0].ports()[0].port(), 4);
	EXPECT_EQ(output.swarm().services()[0].ports()[1].port(), 5);
	EXPECT_EQ(output.swarm().services()[0].mode(), 1);
	EXPECT_EQ(output.swarm().services()[0].aggr_spec_replicas().sum(), 6);
	EXPECT_EQ(output.swarm().services()[0].aggr_tasks().sum(), 7);

	in->add_virtual_ips("4");
	(*in->mutable_ports())[1].set_port(8);
	in->set_spec_replicas(100);
	in->set_tasks(100);

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.swarm().services()[0].virtual_ips().size(), 3);
	EXPECT_EQ(output.swarm().services()[0].virtual_ips()[0], "2");
	EXPECT_EQ(output.swarm().services()[0].virtual_ips()[1], "3");
	EXPECT_EQ(output.swarm().services()[0].virtual_ips()[2], "4");
	EXPECT_EQ(output.swarm().services()[0].ports().size(), 3);
	EXPECT_EQ(output.swarm().services()[0].ports()[0].port(), 4);
	EXPECT_EQ(output.swarm().services()[0].ports()[1].port(), 5);
	EXPECT_EQ(output.swarm().services()[0].ports()[2].port(), 8);
	EXPECT_EQ(output.swarm().services()[0].aggr_spec_replicas().sum(), 106);
	EXPECT_EQ(output.swarm().services()[0].aggr_tasks().sum(), 107);

	// validate primary key
	draiosproto::swarm_service lhs;
	draiosproto::swarm_service rhs;

	rhs.mutable_common()->set_id("1");
	EXPECT_FALSE(swarm_service_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_common()->set_id("");

	rhs.add_virtual_ips("2");
	rhs.add_ports()->set_port(4);
	rhs.set_mode((draiosproto::swarm_service_mode)1);
	rhs.set_spec_replicas(6);
	rhs.set_tasks(7);
	EXPECT_TRUE(swarm_service_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(swarm_service_message_aggregator::hasher()(&lhs),
	          swarm_service_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, swarm_common)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_swarm()->add_services()->mutable_common();
	input.mutable_swarm()->add_nodes();  // swarm needs a node to deliver anything

	in->set_id("1");
	in->set_name("2");
	in->add_labels()->set_key("3");
	in->add_labels()->set_key("4");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.swarm().services()[0].common().id(), "1");
	EXPECT_EQ(output.swarm().services()[0].common().name(), "2");
	EXPECT_EQ(output.swarm().services()[0].common().labels().size(), 2);
	EXPECT_EQ(output.swarm().services()[0].common().labels()[0].key(), "3");
	EXPECT_EQ(output.swarm().services()[0].common().labels()[1].key(), "4");

	(*in->mutable_labels())[0].set_key("5");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.swarm().services()[0].common().labels().size(), 3);
	EXPECT_EQ(output.swarm().services()[0].common().labels()[0].key(), "3");
	EXPECT_EQ(output.swarm().services()[0].common().labels()[1].key(), "4");
	EXPECT_EQ(output.swarm().services()[0].common().labels()[2].key(), "5");

	// validate primary key
	draiosproto::swarm_common lhs;
	draiosproto::swarm_common rhs;

	rhs.set_id("1");
	EXPECT_FALSE(swarm_common_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_id("");

	rhs.set_name("1");
	rhs.add_labels();
	EXPECT_TRUE(swarm_common_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(swarm_common_message_aggregator::hasher()(&lhs),
	          swarm_common_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, swarm_port)
{
	// validate primary key
	draiosproto::swarm_port lhs;
	draiosproto::swarm_port rhs;

	rhs.set_port(1);
	EXPECT_FALSE(swarm_port_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_port(0);
	rhs.set_published_port(1);
	EXPECT_FALSE(swarm_port_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_published_port(0);
	rhs.set_protocol("1");
	EXPECT_FALSE(swarm_port_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_protocol("");

	EXPECT_TRUE(swarm_port_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(swarm_port_message_aggregator::hasher()(&lhs),
	          swarm_port_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, swarm_node)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_swarm()->add_nodes();

	in->mutable_common()->set_id("1");
	in->set_role("2");
	in->set_ip_address("3");
	in->set_version("4");
	in->set_availability("5");
	in->set_state("6");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.swarm().nodes()[0].common().id(), "1");
	EXPECT_EQ(output.swarm().nodes()[0].role(), "2");
	EXPECT_EQ(output.swarm().nodes()[0].ip_address(), "3");
	EXPECT_EQ(output.swarm().nodes()[0].version(), "4");
	EXPECT_EQ(output.swarm().nodes()[0].availability(), "5");
	EXPECT_EQ(output.swarm().nodes()[0].state(), "6");

	in->set_state("1");
	in->set_version("1");
	in->set_availability("1");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.swarm().nodes()[0].state(), "1, 6");
	EXPECT_EQ(output.swarm().nodes()[0].version(), "1, 4");
	EXPECT_EQ(output.swarm().nodes()[0].availability(), "1, 5");
	// validate primary key
	draiosproto::swarm_node lhs;
	draiosproto::swarm_node rhs;

	rhs.mutable_common()->set_id("1");
	EXPECT_FALSE(swarm_node_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_common()->set_id("");

	rhs.set_role("2");
	rhs.set_ip_address("3");
	rhs.set_version("4");
	rhs.set_availability("5");
	rhs.set_state("6");
	rhs.mutable_manager()->set_reachability("asdlfkjka");
	EXPECT_TRUE(swarm_node_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(swarm_node_message_aggregator::hasher()(&lhs),
	          swarm_node_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, swarm_task)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_swarm()->add_tasks();
	input.mutable_swarm()->add_nodes();  // swarm needs a node to deliver anything

	in->mutable_common()->set_id("1");
	in->set_service_id("2");
	in->set_node_id("3");
	in->set_container_id("4");
	in->set_state("5");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.swarm().tasks()[0].common().id(), "1");
	EXPECT_EQ(output.swarm().tasks()[0].service_id(), "2");
	EXPECT_EQ(output.swarm().tasks()[0].node_id(), "3");
	EXPECT_EQ(output.swarm().tasks()[0].container_id(), "4");
	EXPECT_EQ(output.swarm().tasks()[0].state(), "5");

	in->set_state("6");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.swarm().tasks()[0].state(), "5, 6");

	// validate primary key
	draiosproto::swarm_task lhs;
	draiosproto::swarm_task rhs;

	rhs.mutable_common()->set_id("1");
	EXPECT_FALSE(swarm_task_message_aggregator::comparer()(&lhs, &rhs));
	rhs.mutable_common()->set_id("");

	rhs.set_service_id("2");
	rhs.set_node_id("3");
	rhs.set_container_id("4");
	rhs.set_state("5");
	EXPECT_TRUE(swarm_task_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(swarm_task_message_aggregator::hasher()(&lhs),
	          swarm_task_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, swarm_manager)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_swarm()->add_nodes()->mutable_manager();

	in->set_leader(true);
	in->set_reachability("1");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.swarm().nodes()[0].manager().leader(), true);
	EXPECT_EQ(output.swarm().nodes()[0].manager().reachability(), "1");

	in->set_reachability("2");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.swarm().nodes()[0].manager().reachability(), "1, 2");
}

TEST(aggregator, id_map)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_userdb();

	in->set_id(1);
	in->set_name("2");

	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.userdb()[0].id(), 1);
	EXPECT_EQ(output.userdb()[0].name(), "2");

	// validate primary key
	draiosproto::id_map lhs;
	draiosproto::id_map rhs;

	rhs.set_id(1);
	EXPECT_FALSE(id_map_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_id(0);

	rhs.set_name("2");
	EXPECT_TRUE(id_map_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(id_map_message_aggregator::hasher()(&lhs), id_map_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, environment)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.add_environments();

	in->set_hash("1");
	in->add_variables("2");
	in->add_variables("3");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.environments()[0].hash(), "1");
	EXPECT_EQ(output.environments()[0].variables().size(), 2);
	EXPECT_EQ(output.environments()[0].variables()[0], "2");
	EXPECT_EQ(output.environments()[0].variables()[1], "3");
	in->clear_variables();
	in->add_variables("42");
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.environments()[0].hash(), "1");
	EXPECT_EQ(output.environments()[0].variables().size(), 1);
	EXPECT_EQ(output.environments()[0].variables()[0], "42");

	// validate primary key
	draiosproto::environment lhs;
	draiosproto::environment rhs;

	rhs.set_hash("1");
	EXPECT_FALSE(environment_message_aggregator::comparer()(&lhs, &rhs));
	rhs.set_hash("");

	rhs.add_variables();
	EXPECT_TRUE(environment_message_aggregator::comparer()(&lhs, &rhs));
	EXPECT_EQ(environment_message_aggregator::hasher()(&lhs),
	          environment_message_aggregator::hasher()(&rhs));
}

TEST(aggregator, unreported_stats)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	draiosproto::metrics input;
	draiosproto::metrics output;

	auto in = input.mutable_unreported_counters();

	// Everything tested elsewhere except for names
	in->add_names("2");
	in->add_names("3");

	auto input2 = input;
	aggregator->aggregate(input2, output, false);
	EXPECT_EQ(output.unreported_counters().names().size(), 2);
	EXPECT_EQ(output.unreported_counters().names()[0], "2");
	EXPECT_EQ(output.unreported_counters().names()[1], "3");

	(*in->mutable_names())[1] = "4";
	aggregator->aggregate(input, output, false);
	EXPECT_EQ(output.unreported_counters().names().size(), 3);
	EXPECT_EQ(output.unreported_counters().names()[0], "2");
	EXPECT_EQ(output.unreported_counters().names()[1], "3");
	EXPECT_EQ(output.unreported_counters().names()[2], "4");
}

// aggregator extra "tests" are really a utility. SMAGENT-1978
// This one is if-defed because UTs don't play nice with tcmalloc, which is required for
// heap profiling
#if 0
TEST(aggregator_extra, DISABLED_memory_perf)
{
	HeapProfilerStart("small_heap_trace");
	ASSERT_TRUE(IsHeapProfilerRunning());
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator = std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	HeapProfilerDump("fooo");
	for (uint32_t i = 1; i <= 10; i++)
	{
		std::ostringstream filename;
		filename << "goldman_" << i << ".dam";
		std::ifstream input_file;
		input_file.open(filename.str().c_str(), std::ifstream::in | std::ifstream::binary);
		ASSERT_FALSE(input_file.fail());
		input_file.seekg(2);

		draiosproto::metrics* input = new draiosproto::metrics();
		bool success = input->ParseFromIstream(&input_file);
		ASSERT_TRUE(success);
		input_file.close();

		aggregator->aggregate(*input, *output);
		HeapProfilerDump("fooo");
		delete input;
	}
	HeapProfilerStop();
}

TEST(aggregator_extra, DISABLED_cpu_perf)
{
	ProfilerStart("cpu_trace");
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator = std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	for (uint32_t j = 0; j < 10; j++)
	for (uint32_t i = 1; i <= 10; i++)
	{
		std::ostringstream filename;
		filename << "goldman_" << i << ".dam";
		std::ifstream input_file;
		input_file.open(filename.str().c_str(), std::ifstream::in | std::ifstream::binary);
		ASSERT_FALSE(input_file.fail());
		input_file.seekg(2);

		draiosproto::metrics* input = new draiosproto::metrics();
		bool success = input->ParseFromIstream(&input_file);
		ASSERT_TRUE(success);
		input_file.close();

		aggregator->aggregate(*input, *output);
		delete input;
	}
	ProfilerStop();
}
#endif

TEST(aggregator_extra, DISABLED_aggregate)
{
	message_aggregator_builder_impl builder;
	std::unique_ptr<agent_message_aggregator<draiosproto::metrics>> aggregator =
	    std::unique_ptr<agent_message_aggregator<draiosproto::metrics>>(&builder.build_metrics());

	std::ostringstream filename;
	draiosproto::metrics output;
	for (uint32_t i = 0; i <= 9; i++)
	{
		std::ostringstream filename;
		filename << "aggr_pbs/"
		         << "goldman"
		         << "/raw/input_" << i << ".dam";

		std::ifstream input_file;
		input_file.open(filename.str().c_str(), std::ifstream::in | std::ifstream::binary);
		ASSERT_FALSE(input_file.fail());
		input_file.seekg(2);

		draiosproto::metrics* input = new draiosproto::metrics();
		bool success = input->ParseFromIstream(&input_file);
		ASSERT_TRUE(success);
		input_file.close();

		aggregator->aggregate(*input, output, false);
		delete input;
	}

	std::cerr << output.DebugString();
}

TEST(aggregator_extra, DISABLED_dump)
{
	std::ostringstream filename;
	filename << "programs_aggr.dam";

	std::ifstream input_file;
	input_file.open(filename.str().c_str(), std::ifstream::in | std::ifstream::binary);
	ASSERT_FALSE(input_file.fail());
	input_file.seekg(2);

	draiosproto::metrics* input = new draiosproto::metrics();
	bool success = input->ParseFromIstream(&input_file);
	ASSERT_TRUE(success);
	std::cerr << input->DebugString();
	delete input;
}

// A subclass of StreamReporter that suppresses ReportMoved and
// ReportIgnored. We don't care if items move positions, only if their
// contents change, and we don't care that they were ignored.
class IgnoreMovedReporter : public google::protobuf::util::MessageDifferencer::StreamReporter
{
public:
	IgnoreMovedReporter(google::protobuf::io::ZeroCopyOutputStream* output)
	    : google::protobuf::util::MessageDifferencer::StreamReporter(output){};
	IgnoreMovedReporter(google::protobuf::io::Printer* printer)
	    : google::protobuf::util::MessageDifferencer::StreamReporter(printer){};
	virtual ~IgnoreMovedReporter(){};
	virtual void ReportMoved(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path){};
	virtual void ReportIgnored(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path){};
	virtual void ReportAdded(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path)
	{
		// certain repeated fields have limits for objects, and as such, prune their
		// lists to fit that limit. We have no pretense of emitting the exact same
		// ones as the backend. So for this test, we emit all programs, and then
		// simply ignore the extra ones. Some other test validates that we can
		// adhere to a limit when we need to.
		if (field_path.back().field->name() == "programs" ||
		    field_path.back().field->name() == "ipv4_connections")
		{
			return;
		}

		// can't guarantee exact equality of CPD due to its approximation nature
		if (field_path.back().field->containing_type()->name() == "counter_percentile_data")
		{
			return;
		}

		google::protobuf::util::MessageDifferencer::StreamReporter::ReportAdded(message1,
		                                                                        message2,
		                                                                        field_path);
	}
	virtual void ReportModified(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path)
	{
		// can't guarantee exact equality of CPD due to its approximation nature
		if (field_path.back().field->containing_type()->name() == "counter_percentile_data")
		{
			return;
		}

		google::protobuf::util::MessageDifferencer::StreamReporter::ReportModified(message1,
		                                                                           message2,
		                                                                           field_path);
	}
	virtual void ReportDeleted(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path)
	{
		// backend sends an empty field for counters that can't really be replicated
		// in c++. The BE will get defaults, which is still correct.
		if (field_path.back().field->name() == "counters" &&
		    field_path.back().field->containing_type()->name() == "ipv4_connection")
		{
			return;
		}
	}
};

class OnlyDeletedModifiedReporter
    : public google::protobuf::util::MessageDifferencer::StreamReporter
{
public:
	OnlyDeletedModifiedReporter(google::protobuf::io::ZeroCopyOutputStream* output)
	    : google::protobuf::util::MessageDifferencer::StreamReporter(output){};
	OnlyDeletedModifiedReporter(google::protobuf::io::Printer* printer)
	    : google::protobuf::util::MessageDifferencer::StreamReporter(printer){};
	virtual ~OnlyDeletedModifiedReporter(){};
	virtual void ReportAdded(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path){};
	virtual void ReportMoved(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path){};
	virtual void ReportIgnored(
	    const google::protobuf::Message& message1,
	    const google::protobuf::Message& message2,
	    const std::vector<google::protobuf::util::MessageDifferencer::SpecificField>& field_path){};
};

#define TOP(field) GetDescriptor()->FindFieldByName(field)

#define SUB(field) message_type()->FindFieldByName(field)

void ignore_raw_k8s(google::protobuf::util::MessageDifferencer& md,
                    const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("namespace_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("deployment_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("service_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("replicaset_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("job_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("statefulset_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("resourcequota_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("persistentvolumeclaim_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("hpa_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("pod_desired_count"));
	md.IgnoreField(field->SUB("namespaces")->SUB("pod_available_count"));
	md.IgnoreField(field->SUB("nodes")->SUB("capacity_cpu_cores"));
	md.IgnoreField(field->SUB("nodes")->SUB("capacity_mem_bytes"));
	md.IgnoreField(field->SUB("nodes")->SUB("capacity_pods"));
	md.IgnoreField(field->SUB("nodes")->SUB("allocatable_cpu_cores"));
	md.IgnoreField(field->SUB("nodes")->SUB("allocatable_mem_bytes"));
	md.IgnoreField(field->SUB("nodes")->SUB("allocatable_pods"));
	md.IgnoreField(field->SUB("nodes")->SUB("unschedulable"));
	md.IgnoreField(field->SUB("nodes")->SUB("ready"));
	md.IgnoreField(field->SUB("nodes")->SUB("out_of_disk"));
	md.IgnoreField(field->SUB("nodes")->SUB("mem_pressure"));
	md.IgnoreField(field->SUB("nodes")->SUB("disk_pressure"));
	md.IgnoreField(field->SUB("nodes")->SUB("net_unavailable"));
	md.IgnoreField(field->SUB("pods")->SUB("restart_count"));
	md.IgnoreField(field->SUB("pods")->SUB("containers_waiting"));
	md.IgnoreField(field->SUB("pods")->SUB("status_ready"));
	md.IgnoreField(field->SUB("pods")->SUB("requests_cpu_cores"));
	md.IgnoreField(field->SUB("pods")->SUB("limits_cpu_cores"));
	md.IgnoreField(field->SUB("pods")->SUB("requests_mem_bytes"));
	md.IgnoreField(field->SUB("pods")->SUB("limits_mem_bytes"));
	md.IgnoreField(field->SUB("pods")->SUB("restart_rate"));
	md.IgnoreField(field->SUB("controllers")->SUB("replicas_desired"));
	md.IgnoreField(field->SUB("controllers")->SUB("replicas_running"));
	md.IgnoreField(field->SUB("controllers")->SUB("replicas_fully_labeled"));
	md.IgnoreField(field->SUB("controllers")->SUB("replicas_ready"));
	md.IgnoreField(field->SUB("controllers")->SUB("replicas_available"));
	md.IgnoreField(field->SUB("replica_sets")->SUB("replicas_desired"));
	md.IgnoreField(field->SUB("replica_sets")->SUB("replicas_running"));
	md.IgnoreField(field->SUB("replica_sets")->SUB("replicas_fully_labeled"));
	md.IgnoreField(field->SUB("replica_sets")->SUB("replicas_ready"));
	md.IgnoreField(field->SUB("deployments")->SUB("replicas_desired"));
	md.IgnoreField(field->SUB("deployments")->SUB("replicas_running"));
	md.IgnoreField(field->SUB("deployments")->SUB("replicas_avaialable"));
	md.IgnoreField(field->SUB("deployments")->SUB("replicas_updated"));
	md.IgnoreField(field->SUB("deployments")->SUB("replicas_paused"));
	md.IgnoreField(field->SUB("daemonsets")->SUB("current_scheduled"));
	md.IgnoreField(field->SUB("daemonsets")->SUB("desired_scheduled"));
	md.IgnoreField(field->SUB("daemonsets")->SUB("pods_misscheduled"));
	md.IgnoreField(field->SUB("daemonsets")->SUB("pods_ready"));
	md.IgnoreField(field->SUB("jobs")->SUB("parallelism"));
	md.IgnoreField(field->SUB("jobs")->SUB("completions"));
	md.IgnoreField(field->SUB("jobs")->SUB("status_active"));
	md.IgnoreField(field->SUB("jobs")->SUB("num_succeeded"));
	md.IgnoreField(field->SUB("jobs")->SUB("num_failed"));
	md.IgnoreField(field->SUB("statefulsets")->SUB("replicas"));
	md.IgnoreField(field->SUB("statefulsets")->SUB("status_replicas"));
	md.IgnoreField(field->SUB("statefulsets")->SUB("status_replicas_current"));
	md.IgnoreField(field->SUB("statefulsets")->SUB("status_replicas_ready"));
	md.IgnoreField(field->SUB("statefulsets")->SUB("status_replicas_updated"));
	md.IgnoreField(field->SUB("hpas")->SUB("replicas_min"));
	md.IgnoreField(field->SUB("hpas")->SUB("replicas_max"));
	md.IgnoreField(field->SUB("hpas")->SUB("replicas_current"));
	md.IgnoreField(field->SUB("hpas")->SUB("replicas_desired"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("limits_cpu_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("limits_memory_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("requests_cpu_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("requests_memory_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("limits_cpu_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("limit_memory_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("requests_cpu_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("requests_memory_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("double_limits_cpu_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("duoble_requests_cpu_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("double_limits_cpu_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("double_requests_cpu_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("requests_storage_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("requests_storage_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("configmaps_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("persistentvolumeclaims_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("pods_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("replicationcontrollers_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("resourcequotas_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("services_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("services_loadbalancers_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("services_nodeports_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("secrets_hard"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("configmaps_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("persistentvolumeclaims_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("pods_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("replicationcontrollers_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("resourcequotas_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("services_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("services_loadbalancers_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("services_nodeports_used"));
	md.IgnoreField(field->SUB("resourcequotas")->SUB("secrets_used"));
	md.IgnoreField(field->SUB("persistentvolumes")->SUB("storage"));
	md.IgnoreField(field->SUB("persistentvolumeclaims")->SUB("storage"));
}

void ignore_raw_counter_time(google::protobuf::util::MessageDifferencer& md,
                             const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("time_ns"));
	md.IgnoreField(field->SUB("count"));
}

void ignore_raw_counter_time_bytes(google::protobuf::util::MessageDifferencer& md,
                                   const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("time_ns_in"));
	md.IgnoreField(field->SUB("time_ns_out"));
	md.IgnoreField(field->SUB("time_ns_other"));
	md.IgnoreField(field->SUB("count_in"));
	md.IgnoreField(field->SUB("count_out"));
	md.IgnoreField(field->SUB("count_other"));
	md.IgnoreField(field->SUB("bytes_in"));
	md.IgnoreField(field->SUB("bytes_out"));
	md.IgnoreField(field->SUB("bytes_other"));
}

void ignore_raw_counter_bytes(google::protobuf::util::MessageDifferencer& md,
                              const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("count_in"));
	md.IgnoreField(field->SUB("count_out"));
	md.IgnoreField(field->SUB("bytes_in"));
	md.IgnoreField(field->SUB("bytes_out"));
}

void ignore_raw_time_categories(google::protobuf::util::MessageDifferencer& md,
                                const google::protobuf::FieldDescriptor* field)
{
	ignore_raw_counter_time(md, field->SUB("other"));
	ignore_raw_counter_time_bytes(md, field->SUB("io_file"));
	ignore_raw_counter_time_bytes(md, field->SUB("io_net"));
	ignore_raw_counter_time(md, field->SUB("processing"));
}

void ignore_raw_counter_time_bidirectional(google::protobuf::util::MessageDifferencer& md,
                                           const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("count_in"));
	md.IgnoreField(field->SUB("count_out"));
	md.IgnoreField(field->SUB("time_ns_in"));
	md.IgnoreField(field->SUB("time_ns_out"));
}

void ignore_raw_counter_syscall_errors(google::protobuf::util::MessageDifferencer& md,
                                       const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("count"));
}

void ignore_raw_mounted_fs(google::protobuf::util::MessageDifferencer& md,
                           const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("size_bytes"));
	md.IgnoreField(field->SUB("used_bytes"));
	md.IgnoreField(field->SUB("available_bytes"));
}

void ignore_raw_connection_categories(google::protobuf::util::MessageDifferencer& md,
                                      const google::protobuf::FieldDescriptor* field)
{
	ignore_raw_counter_bytes(md, field->SUB("server"));
	ignore_raw_counter_bytes(md, field->SUB("client"));
}

void ignore_raw_file_stat(google::protobuf::util::MessageDifferencer& md,
                          const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("bytes"));
	md.IgnoreField(field->SUB("errors"));
	md.IgnoreField(field->SUB("time_ns"));
	md.IgnoreField(field->SUB("open_count"));
}

void ignore_raw_protos(google::protobuf::util::MessageDifferencer& md,
                       const google::protobuf::FieldDescriptor* field)
{
	md.IgnoreField(field->SUB("mongodb")->SUB("server_totals")->SUB("ncalls"));
	md.IgnoreField(field->SUB("mongodb")->SUB("server_totals")->SUB("time_tot"));
	md.IgnoreField(field->SUB("mongodb")->SUB("server_totals")->SUB("time_max"));
	md.IgnoreField(field->SUB("mongodb")->SUB("server_totals")->SUB("bytes_in"));
	md.IgnoreField(field->SUB("mongodb")->SUB("server_totals")->SUB("bytes_out"));
	md.IgnoreField(field->SUB("mongodb")->SUB("server_totals")->SUB("nerrors"));
	md.IgnoreField(field->SUB("mongodb")->SUB("client_totals")->SUB("ncalls"));
	md.IgnoreField(field->SUB("mongodb")->SUB("client_totals")->SUB("time_tot"));
	md.IgnoreField(field->SUB("mongodb")->SUB("client_totals")->SUB("time_max"));
	md.IgnoreField(field->SUB("mongodb")->SUB("client_totals")->SUB("bytes_in"));
	md.IgnoreField(field->SUB("mongodb")->SUB("client_totals")->SUB("bytes_out"));
	md.IgnoreField(field->SUB("mongodb")->SUB("client_totals")->SUB("nerrors"));
	md.IgnoreField(field->SUB("http")->SUB("server_status_codes")->SUB("ncalls"));
	md.IgnoreField(field->SUB("http")->SUB("client_status_codes")->SUB("ncalls"));
}

// the collector reports 0 for the raw value of aggregated metrics. We don't explicitly
// set it, as it is ignored by the backend. This function sets the differ to
// ignore all those fields
void ignore_raw_fields(google::protobuf::util::MessageDifferencer& md,
                       draiosproto::metrics& message)
{
	md.IgnoreField(message.TOP("hostinfo")->SUB("physical_memory_size_bytes"));
	ignore_raw_time_categories(md, message.TOP("hostinfo")->SUB("tcounters"));
	ignore_raw_counter_syscall_errors(md, message.TOP("hostinfo")->SUB("syscall_errors"));
	ignore_raw_counter_time_bidirectional(md,
	                                      message.TOP("hostinfo")->SUB("max_transaction_counters"));

	ignore_raw_mounted_fs(md, message.TOP("containers")->SUB("mounts"));
	ignore_raw_connection_categories(
	    md,
	    message.TOP("hostinfo")->SUB("network_by_serverports")->SUB("counters"));
	ignore_raw_file_stat(md, message.TOP("top_devices"));
	ignore_raw_protos(md, message.TOP("unreported_counters")->SUB("protos"));
	ignore_raw_k8s(md, message.TOP("kubernetes"));
	ignore_raw_k8s(md, message.TOP("global_kubernetes"));
}

void map_k8s(google::protobuf::util::MessageDifferencer& md,
             const google::protobuf::FieldDescriptor* field)
{
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("namespaces"),
	    {{field->SUB("namespaces")->SUB("common"),
	      field->SUB("namespaces")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("nodes"),
	    {{field->SUB("nodes")->SUB("common"), field->SUB("nodes")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("pods"),
	    {{field->SUB("pods")->SUB("common"), field->SUB("pods")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("controllers"),
	    {{field->SUB("controllers")->SUB("common"),
	      field->SUB("controllers")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(field->SUB("services"),
	                                         {{field->SUB("services")->SUB("common"),
	                                           field->SUB("services")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("replica_sets"),
	    {{field->SUB("replica_sets")->SUB("common"),
	      field->SUB("replica_sets")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("deployments"),
	    {{field->SUB("deployments")->SUB("common"),
	      field->SUB("deployments")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("daemonsets"),
	    {{field->SUB("daemonsets")->SUB("common"),
	      field->SUB("daemonsets")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("jobs"),
	    {{field->SUB("jobs")->SUB("common"), field->SUB("jobs")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("statefulsets"),
	    {{field->SUB("statefulsets")->SUB("common"),
	      field->SUB("statefulsets")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("resourcequotas"),
	    {{field->SUB("resourcequotas")->SUB("common"),
	      field->SUB("resourcequotas")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("persistentvolumes"),
	    {{field->SUB("persistentvolumes")->SUB("common"),
	      field->SUB("persistentvolumes")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("persistentvolumeclaims"),
	    {{field->SUB("persistentvolumeclaims")->SUB("common"),
	      field->SUB("persistentvolumeclaims")->SUB("common")->SUB("uid")}});
}

void map_percentile(google::protobuf::util::MessageDifferencer& md,
                    const google::protobuf::FieldDescriptor* field)
{
	md.TreatAsMap(field, field->SUB("percentile"));
}

void map_time_categories(google::protobuf::util::MessageDifferencer& md,
                         const google::protobuf::FieldDescriptor* field)
{
	map_percentile(md, field->SUB("unknown")->SUB("percentile"));
	map_percentile(md, field->SUB("other")->SUB("percentile"));
	map_percentile(md, field->SUB("file")->SUB("percentile"));
	map_percentile(md, field->SUB("net")->SUB("percentile"));
	map_percentile(md, field->SUB("ipc")->SUB("percentile"));
	map_percentile(md, field->SUB("memory")->SUB("percentile"));
	map_percentile(md, field->SUB("process")->SUB("percentile"));
	map_percentile(md, field->SUB("sleep")->SUB("percentile"));
	map_percentile(md, field->SUB("system")->SUB("percentile"));
	map_percentile(md, field->SUB("signal")->SUB("percentile"));
	map_percentile(md, field->SUB("user")->SUB("percentile"));
	map_percentile(md, field->SUB("time")->SUB("percentile"));
	map_percentile(md, field->SUB("io_file")->SUB("percentile_in"));
	map_percentile(md, field->SUB("io_file")->SUB("percentile_out"));
	map_percentile(md, field->SUB("io_net")->SUB("percentile_in"));
	map_percentile(md, field->SUB("io_net")->SUB("percentile_out"));
	map_percentile(md, field->SUB("io_other")->SUB("percentile_in"));
	map_percentile(md, field->SUB("io_other")->SUB("percentile_out"));
	map_percentile(md, field->SUB("wait")->SUB("percentile"));
	map_percentile(md, field->SUB("processing")->SUB("percentile"));
}

void map_protos(google::protobuf::util::MessageDifferencer& md,
                const google::protobuf::FieldDescriptor* field)
{
	md.TreatAsMap(field->SUB("mongodb")->SUB("client_collections"),
	              field->SUB("mongodb")->SUB("client_collections")->SUB("name"));
	md.TreatAsMap(field->SUB("mongodb")->SUB("server_collections"),
	              field->SUB("mongodb")->SUB("server_collections")->SUB("name"));
	md.TreatAsMap(field->SUB("mongodb")->SUB("client_ops"),
	              field->SUB("mongodb")->SUB("client_ops")->SUB("op"));
	md.TreatAsMap(field->SUB("mongodb")->SUB("servers_ops"),
	              field->SUB("mongodb")->SUB("servers_ops")->SUB("op"));
	md.TreatAsMap(field->SUB("postgres")->SUB("client_query_types"),
	              field->SUB("postgres")->SUB("client_query_types")->SUB("type"));
	md.TreatAsMap(field->SUB("postgres")->SUB("server_query_types"),
	              field->SUB("postgres")->SUB("server_query_types")->SUB("type"));
	md.TreatAsMap(field->SUB("postgres")->SUB("client_tables"),
	              field->SUB("postgres")->SUB("client_tables")->SUB("name"));
	md.TreatAsMap(field->SUB("postgres")->SUB("server_tables"),
	              field->SUB("postgres")->SUB("server_tables")->SUB("name"));
	md.TreatAsMap(field->SUB("postgres")->SUB("server_queries"),
	              field->SUB("postgres")->SUB("server_queries")->SUB("name"));
	md.TreatAsMap(field->SUB("mysql")->SUB("client_query_types"),
	              field->SUB("mysql")->SUB("client_query_types")->SUB("type"));
	md.TreatAsMap(field->SUB("mysql")->SUB("server_query_types"),
	              field->SUB("mysql")->SUB("server_query_types")->SUB("type"));
	md.TreatAsMap(field->SUB("mysql")->SUB("client_queries"),
	              field->SUB("mysql")->SUB("client_queries")->SUB("name"));
	md.TreatAsMap(field->SUB("mysql")->SUB("client_tables"),
	              field->SUB("mysql")->SUB("client_tables")->SUB("name"));
	md.TreatAsMap(field->SUB("mysql")->SUB("server_tables"),
	              field->SUB("mysql")->SUB("server_tables")->SUB("name"));
	md.TreatAsMap(field->SUB("http")->SUB("client_urls"),
	              field->SUB("http")->SUB("client_urls")->SUB("url"));
	md.TreatAsMap(field->SUB("http")->SUB("server_urls"),
	              field->SUB("http")->SUB("server_urls")->SUB("url"));
	md.TreatAsMap(field->SUB("http")->SUB("server_status_codes"),
	              field->SUB("http")->SUB("server_status_codes")->SUB("status_code"));
	md.TreatAsMap(field->SUB("http")->SUB("client_status_codes"),
	              field->SUB("http")->SUB("client_status_codes")->SUB("status_code"));
	md.TreatAsMap(field->SUB("app")->SUB("checks"), field->SUB("app")->SUB("checks")->SUB("name"));
	md.TreatAsMap(field->SUB("app")->SUB("checks")->SUB("tags"),
	              field->SUB("app")->SUB("checks")->SUB("tags")->SUB("key"));

	// SMAGENT-2624: The app_tag message now has two primary keys: key and value. However,
	//               it's non-trivial to regenerate the set of protobufs used for
	//               comparison so for right now this function will continue validating
	//               the old behavior

	md.TreatAsMapWithMultipleFieldsAsKey(field->SUB("app")->SUB("metrics"),
	                                     {field->SUB("app")->SUB("metrics")->SUB("name"),
	                                      field->SUB("app")->SUB("metrics")->SUB("tags")});
	md.TreatAsSet(field->SUB("app")->SUB("metrics")->SUB("tags"));

	md.TreatAsMap(field->SUB("java")->SUB("beans"), field->SUB("java")->SUB("beans")->SUB("name"));
	md.TreatAsMap(field->SUB("java")->SUB("beans")->SUB("attributes"),
	              field->SUB("java")->SUB("beans")->SUB("attributes")->SUB("name"));
	md.TreatAsMap(
	    field->SUB("java")->SUB("beans")->SUB("attributes")->SUB("subattributes"),
	    field->SUB("java")->SUB("beans")->SUB("attributes")->SUB("subattributes")->SUB("name"));
	md.TreatAsMapWithMultipleFieldsAsKey(
	    field->SUB("statsd")->SUB("statsd_metrics"),
	    {field->SUB("statsd")->SUB("statsd_metrics")->SUB("name"),
	     field->SUB("statsd")->SUB("statsd_metrics")->SUB("tags")});
	md.TreatAsSet(field->SUB("statsd")->SUB("statsd_metrics")->SUB("tags"));
}

void map_swarm(google::protobuf::util::MessageDifferencer& md,
               const google::protobuf::FieldDescriptor* field)
{
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("tasks"),
	    {{field->SUB("tasks")->SUB("common"), field->SUB("tasks")->SUB("common")->SUB("id")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("nodes"),
	    {{field->SUB("nodes")->SUB("common"), field->SUB("nodes")->SUB("common")->SUB("id")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(field->SUB("services"),
	                                         {{field->SUB("services")->SUB("common"),
	                                           field->SUB("services")->SUB("common")->SUB("id")}});
	md.TreatAsMap(field->SUB("tasks")->SUB("common")->SUB("labels"),
	              field->SUB("tasks")->SUB("common")->SUB("labels")->SUB("key"));
	md.TreatAsMap(field->SUB("nodes")->SUB("common")->SUB("labels"),
	              field->SUB("nodes")->SUB("common")->SUB("labels")->SUB("key"));
	md.TreatAsMap(field->SUB("services")->SUB("common")->SUB("labels"),
	              field->SUB("services")->SUB("common")->SUB("labels")->SUB("key"));
	md.TreatAsSet(field->SUB("services")->SUB("ports"));
	md.TreatAsSet(field->SUB("services")->SUB("virtual_ips"));
}

void map_mesos(google::protobuf::util::MessageDifferencer& md,
               const google::protobuf::FieldDescriptor* field)
{
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("frameworks"),
	    {{field->SUB("frameworks")->SUB("common"),
	      field->SUB("frameworks")->SUB("common")->SUB("uid")}});
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("frameworks")->SUB("tasks"),
	    {{field->SUB("frameworks")->SUB("tasks")->SUB("common"),
	      field->SUB("frameworks")->SUB("tasks")->SUB("common")->SUB("uid")}});
	md.TreatAsMap(field->SUB("frameworks")->SUB("common")->SUB("labels"),
	              field->SUB("frameworks")->SUB("common")->SUB("labels")->SUB("key"));
	md.TreatAsMap(field->SUB("frameworks")->SUB("tasks")->SUB("common")->SUB("labels"),
	              field->SUB("frameworks")->SUB("tasks")->SUB("common")->SUB("labels")->SUB("key"));
	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    field->SUB("slaves"),
	    {{field->SUB("slaves")->SUB("common"), field->SUB("slaves")->SUB("common")->SUB("uid")}});
	md.TreatAsMap(field->SUB("groups"), field->SUB("groups")->SUB("id"));
	md.TreatAsMap(field->SUB("groups")->SUB("apps"), field->SUB("groups")->SUB("apps")->SUB("id"));
	md.TreatAsSet(field->SUB("groups")->SUB("apps")->SUB("task_ids"));
	md.TreatAsMap(field->SUB("groups")->SUB("groups"),
	              field->SUB("groups")->SUB("groups")->SUB("id"));
}

void map_containers(google::protobuf::util::MessageDifferencer& md,
                    const google::protobuf::FieldDescriptor* field)
{
	md.TreatAsMap(field->SUB("top_devices"), field->SUB("top_devices")->SUB("name"));
	md.TreatAsMap(field->SUB("top_files"), field->SUB("top_files")->SUB("name"));
	md.TreatAsMap(field->SUB("mounts"), field->SUB("mounts")->SUB("mount_dir"));
	md.TreatAsSet(field->SUB("container_reporting_group_id"));
	md.TreatAsSet(field->SUB("orchestrators_fallback_labels"));
	md.TreatAsMapWithMultipleFieldsAsKey(
	    field->SUB("labels"),
	    {field->SUB("labels")->SUB("key"), field->SUB("labels")->SUB("value")});
	md.TreatAsMap(field->SUB("network_by_serverports"),
	              field->SUB("network_by_serverports")->SUB("port"));
	md.TreatAsMap(field->SUB("mounts"), field->SUB("mounts")->SUB("mount_dir"));
	md.TreatAsSet(field->SUB("port_mappings"));
	map_protos(md, field->SUB("protos"));
}

void validate_protobuf(std::string& diff, const std::string& name, bool should_ignore_raw_fields)
{
	// first generate the aggregated protobuf
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl* aggregator = new metrics_message_aggregator_impl(builder);
	draiosproto::metrics test;
	std::ostringstream filename;

	for (uint32_t i = 0; i < 10; i++)
	{
		std::ostringstream filename;
		filename << "aggr_pbs/" << name << "/raw/input_" << i << ".dam";
		std::ifstream input_file;
		input_file.open(filename.str().c_str(), std::ifstream::in | std::ifstream::binary);
		ASSERT_FALSE(input_file.fail());
		input_file.seekg(2);

		draiosproto::metrics input;
		bool success = input.ParseFromIstream(&input_file);
		ASSERT_TRUE(success);
		input_file.close();

		// aggregator depends on this field being set, but it isn't in the canonical
		// protobus, and I don't feel like regenerating them. so populate it now
		for (int i = 0; i < input.programs().size(); i++)
		{
			(*input.mutable_programs())[i].set_tiuid(
			    draiosproto::program_java_hasher(input.programs()[i]));
		}
		aggregator->aggregate(input, test, false);
	}
	aggregator->override_primary_keys(test);
	delete aggregator;

	// now parse the backend protobuf
	std::ostringstream backend_filename;
	backend_filename << "aggr_pbs/" << name << "/aggregated.dam";
	draiosproto::metrics backend;
	std::ifstream backend_stream;
	backend_stream.open(backend_filename.str().c_str(), std::ifstream::in | std::ifstream::binary);
	ASSERT_FALSE(backend_stream.fail());
	backend_stream.seekg(2);
	ASSERT_TRUE(backend.ParseFromIstream(&backend_stream));

	// now diff
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	google::protobuf::util::MessageDifferencer md;

	md.TreatAsMapWithMultipleFieldsAsKey(backend.TOP("ipv4_connections"),
	                                     {backend.TOP("ipv4_connections")->SUB("tuple"),
	                                      backend.TOP("ipv4_connections")->SUB("spid"),
	                                      backend.TOP("ipv4_connections")->SUB("dpid")});
	md.TreatAsMap(backend.TOP("mounts"), backend.TOP("mounts")->SUB("mount_dir"));
	md.TreatAsSet(backend.TOP("top_files"));
	md.TreatAsMap(backend.TOP("containers"), backend.TOP("containers")->SUB("id"));
	map_containers(md, backend.TOP("containers"));
	md.TreatAsSet(backend.TOP("userdb"));

	md.TreatAsMapWithMultipleFieldPathsAsKey(
	    backend.TOP("programs"),
	    {{backend.TOP("programs")->SUB("procinfo"),
	      backend.TOP("programs")->SUB("procinfo")->SUB("details")},
	     {backend.TOP("programs")->SUB("environment_hash")}});

	map_k8s(md, backend.TOP("kubernetes"));

	md.TreatAsMap(backend.TOP("programs")->SUB("procinfo")->SUB("top_files"),
	              backend.TOP("programs")->SUB("procinfo")->SUB("top_files")->SUB("name"));
	md.TreatAsMap(backend.TOP("programs")->SUB("procinfo")->SUB("top_devices"),
	              backend.TOP("programs")->SUB("procinfo")->SUB("top_devices")->SUB("name"));
	md.TreatAsSet(backend.TOP("programs")->SUB("pids"));
	md.TreatAsSet(backend.TOP("programs")->SUB("uids"));
	map_protos(md, backend.TOP("programs")->SUB("procinfo")->SUB("protos"));
	md.TreatAsSet(backend.TOP("hostinfo")->SUB("syscall_errors")->SUB("top_error_codes"));
	md.TreatAsMap(backend.TOP("hostinfo")->SUB("network_by_serverports"),
	              backend.TOP("hostinfo")->SUB("network_by_serverports")->SUB("port"));
	md.TreatAsMap(backend.TOP("top_devices"), backend.TOP("top_devices")->SUB("name"));

	map_time_categories(md, backend.TOP("hostinfo")->SUB("tcounters"));
	map_protos(md, backend.TOP("unreported_counters")->SUB("protos"));
	map_protos(md, backend.TOP("protos"));
	map_swarm(md, backend.TOP("swarm"));
	map_mesos(md, backend.TOP("mesos"));

	md.TreatAsMap(backend.TOP("environments"), backend.TOP("environments")->SUB("hash"));
	md.TreatAsSet(backend.TOP("environments")->SUB("variables"));
	md.TreatAsMapWithMultipleFieldsAsKey(backend.TOP("ipv4_network_interfaces"),
	                                     {backend.TOP("ipv4_network_interfaces")->SUB("addr"),
	                                      backend.TOP("ipv4_network_interfaces")->SUB("netmask"),
	                                      backend.TOP("ipv4_network_interfaces")->SUB("bcast")});

	// ignore non-aggregated values
	if (should_ignore_raw_fields)
	{
		ignore_raw_fields(md, backend);
	}

	// no guarantee timestamp will match. this is ok.
	md.IgnoreField(backend.TOP("timestamp_ns"));
	md.IgnoreField(backend.TOP("events"));  // timestamp is primary key, so can't compare since
	                                        // BE overwrites it
	// for these three, if the value changes, any value is fair game
	md.IgnoreField(backend.TOP("unreported_counters")
	                   ->SUB("protos")
	                   ->SUB("java")
	                   ->SUB("beans")
	                   ->SUB("attributes")
	                   ->SUB("scale"));
	md.IgnoreField(backend.TOP("unreported_counters")
	                   ->SUB("protos")
	                   ->SUB("java")
	                   ->SUB("beans")
	                   ->SUB("attributes")
	                   ->SUB("unit"));
	md.IgnoreField(backend.TOP("unreported_counters")
	                   ->SUB("protos")
	                   ->SUB("java")
	                   ->SUB("beans")
	                   ->SUB("attributes")
	                   ->SUB("alias"));
	md.IgnoreField(backend.TOP("swarm")->SUB("tasks")->SUB("common")->SUB("labels")->SUB("value"));
	md.IgnoreField(backend.TOP("swarm")->SUB("nodes")->SUB("common")->SUB("labels")->SUB("value"));
	md.IgnoreField(backend.TOP("swarm")->SUB("nodes")->SUB("common")->SUB("name"));
	md.IgnoreField(backend.TOP("swarm")->SUB("tasks")->SUB("common")->SUB("name"));
	md.IgnoreField(backend.TOP("swarm")->SUB("tasks")->SUB("service_id"));
	md.IgnoreField(backend.TOP("swarm")->SUB("tasks")->SUB("container_id"));
	md.IgnoreField(backend.TOP("swarm")->SUB("nodes")->SUB("ip_address"));
	md.IgnoreField(backend.TOP("swarm")->SUB("nodes")->SUB("role"));
	md.IgnoreField(backend.TOP("mesos")->SUB("slaves")->SUB("common")->SUB("labels")->SUB("value"));
	md.IgnoreField(backend.TOP("mesos")->SUB("slaves")->SUB("common")->SUB("name"));
	md.IgnoreField(backend.TOP("mesos")->SUB("frameworks")->SUB("tasks")->SUB("slave_id"));
	md.IgnoreField(backend.TOP("containers")->SUB("mounts")->SUB("device"));
	md.IgnoreField(backend.TOP("containers")->SUB("mounts")->SUB("type"));
	md.IgnoreField(backend.TOP("ipv4_network_interfaces")->SUB("name"));
	md.IgnoreField(backend.TOP("sampling_ratio"));
	md.IgnoreField(backend.TOP("userdb")->SUB("name"));
	md.IgnoreField(backend.TOP("machine_id"));
	md.IgnoreField(backend.TOP("customer_id"));
	md.IgnoreField(backend.TOP("swarm")->SUB("tasks")->SUB("node_id"));
	md.IgnoreField(backend.TOP("swarm")->SUB("nodes")->SUB("manager")->SUB("leader"));
	md.IgnoreField(backend.TOP("swarm")->SUB("services")->SUB("mode"));
	md.IgnoreField(backend.TOP("environments")->SUB("variables"));
	md.IgnoreField(backend.TOP("programs")
	                   ->SUB("procinfo")
	                   ->SUB("protos")
	                   ->SUB("app")
	                   ->SUB("checks")
	                   ->SUB("tags")
	                   ->SUB("value"));
	md.IgnoreField(
	    backend.TOP("unreported_counters")->SUB("protos")->SUB("app")->SUB("checks")->SUB("value"));
	md.IgnoreField(backend.TOP("ipv4_connections")->SUB("error_code"));

	// BE has a limit on attribute count limit which can cause the aggregated stat
	// value to mismatch
	md.IgnoreField(backend.TOP("containers")
	                   ->SUB("protos")
	                   ->SUB("java")
	                   ->SUB("beans")
	                   ->SUB("attributes")
	                   ->SUB("subattributes")
	                   ->SUB("aggr_value_double"));

	// as of when the protobufs were created, backend didn't support these fields.
	// If the protobufs are regenerated and BE has added support, this can be removed
	md.IgnoreField(
	    backend.TOP("containers")->SUB("resource_counters")->SUB("aggr_proc_start_count"));
	md.IgnoreField(backend.TOP("hostinfo")->SUB("aggr_system_load"));
	md.IgnoreField(backend.TOP("unreported_counters")->SUB("transaction_counters"));
	md.IgnoreField(backend.TOP("unreported_counters")
	                   ->SUB("protos")
	                   ->SUB("java")
	                   ->SUB("beans")
	                   ->SUB("attributes")
	                   ->SUB("segment_by"));
	md.IgnoreField(backend.TOP("reporting_groups"));
	md.IgnoreField(backend.TOP("unreported_counters")->SUB("names"));
	md.IgnoreField(backend.TOP("internal_metrics"));
	md.IgnoreField(backend.TOP("config_percentiles"));
	md.IgnoreField(backend.TOP("commands"));
	md.IgnoreField(backend.TOP("falcobl"));
	md.IgnoreField(backend.TOP("containers")->SUB("commands"));
	md.IgnoreField(backend.TOP("ipv4_incomplete_connections"));  // we only use v2
	md.IgnoreField(backend.TOP("ipv4_incomplete_connections_v2"));
	md.IgnoreField(backend.TOP("programs")->SUB("program_reporting_group_id"));
	// Due to the change in fields, we cannot compare prometheus
	md.IgnoreField(backend.TOP("unreported_counters")->SUB("protos")->SUB("prometheus"));
	md.IgnoreField(backend.TOP("programs")
	                   ->SUB("procinfo")
	                   ->SUB("protos")
	                   ->SUB("app")
	                   ->SUB("metrics")
	                   ->SUB("prometheus_type"));
	md.IgnoreField(backend.TOP("programs")
	                   ->SUB("procinfo")
	                   ->SUB("protos")
	                   ->SUB("app")
	                   ->SUB("metrics")
	                   ->SUB("buckets"));
	md.IgnoreField(backend.TOP("programs")->SUB("tiuid"));
	// reporter needs to fall out of scope to flush
	{
		google::protobuf::io::StringOutputStream output_stream(&diff);
		IgnoreMovedReporter reporter(&output_stream);
		md.ReportDifferencesTo(&reporter);

		md.Compare(backend, test);
	}

	std::cerr << diff;
}

TEST(validate_aggregator, DISABLED_50_k8s)
{
	std::string diff;
	validate_protobuf(diff, "50-k8s-3600", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_5_k8s)
{
	std::string diff;
	validate_protobuf(diff, "5-k8s", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_admin)
{
	std::string diff;
	validate_protobuf(diff, "admin_8968", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_compliance)
{
	std::string diff;
	validate_protobuf(diff, "compliance-k8s", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_custom_container)
{
	std::string diff;
	validate_protobuf(diff, "custom-containers", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_custom_metric)
{
	std::string diff;
	validate_protobuf(diff, "custom-metric-issue", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, goldman)
{
	std::string diff;
	validate_protobuf(diff, "goldman", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_host)
{
	std::string diff;
	validate_protobuf(diff, "host-60", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_istio)
{
	std::string diff;
	validate_protobuf(diff, "istio", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_openshift)
{
	std::string diff;
	validate_protobuf(diff, "k8s-openshift-original", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_load)
{
	std::string diff;
	validate_protobuf(diff, "load", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_mesos)
{
	std::string diff;
	validate_protobuf(diff, "mesos", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_openshift_100)
{
	std::string diff;
	validate_protobuf(diff, "openshift-100-node-cluser", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_openshift_big_k8s)
{
	std::string diff;
	validate_protobuf(diff, "openshift-50-node-cluster-with-lots-of-k8s-objects", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_prometheus)
{
	std::string diff;
	validate_protobuf(diff, "prometheus", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_random)
{
	std::string diff;
	validate_protobuf(diff, "random", true);
	EXPECT_EQ(diff.size(), 0);
}
TEST(validate_aggregator, DISABLED_swarm)
{
	std::string diff;
	validate_protobuf(diff, "swarm", true);
	EXPECT_EQ(diff.size(), 0);
}

void generate_k8s_common(draiosproto::k8s_common* input)
{
	input->set_name(std::to_string(rand()));
	input->set_uid(std::to_string(rand() % 10));
	input->set_namespace_(std::to_string(rand()));
	input->add_labels()->set_key(std::to_string(rand() % 2));
	(*input->mutable_labels())[0].set_value(std::to_string(rand() % 2));
	input->add_labels()->set_key(std::to_string(rand() % 2));
	(*input->mutable_labels())[1].set_value(std::to_string(rand() % 2));
	input->add_selectors()->set_key(std::to_string(rand() % 2));
	(*input->mutable_selectors())[0].set_value(std::to_string(rand() % 2));
	input->add_selectors()->set_key(std::to_string(rand() % 2));
	(*input->mutable_selectors())[1].set_value(std::to_string(rand() % 2));
}

void generate_k8s(draiosproto::k8s_state* input)
{
	input->set_cluster_id("a;lsjkodf");
	input->set_cluster_name("asd;fioj");
	input->set_namespace_count(rand() % 100);
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_namespaces();
		generate_k8s_common(j->mutable_common());
		j->set_deployment_count(rand() % 100);
		j->set_service_count(rand() % 100);
		j->set_replicaset_count(rand() % 100);
		j->set_job_count(rand() % 100);
		j->set_statefulset_count(rand() % 100);
		j->set_resourcequota_count(rand() % 100);
		j->set_persistentvolumeclaim_count(rand() % 100);
		j->set_hpa_count(rand() % 100);
		j->set_pod_desired_count(rand() % 100);
		j->set_pod_available_count(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_nodes();
		generate_k8s_common(j->mutable_common());
		j->add_host_ips(std::to_string(rand() % 4));
		j->add_host_ips(std::to_string(rand() % 4));
		j->set_capacity_cpu_cores(rand() % 100);
		j->set_capacity_mem_bytes(rand() % 100);
		j->set_capacity_pods(rand() % 100);
		j->set_allocatable_cpu_cores(rand() % 100);
		j->set_allocatable_mem_bytes(rand() % 100);
		j->set_allocatable_pods(rand() % 100);
		j->set_unschedulable(rand() % 100);
		j->set_ready(rand() % 100);
		j->set_out_of_disk(rand() % 100);
		j->set_mem_pressure(rand() % 100);
		j->set_disk_pressure(rand() % 100);
		j->set_net_unavailable(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_pods();
		generate_k8s_common(j->mutable_common());
		j->add_container_ids(std::to_string(rand() % 4));
		j->add_container_ids(std::to_string(rand() % 4));
		j->set_node_name(std::to_string(rand() % 2));
		j->set_host_ip(std::to_string(rand() % 2));
		j->set_internal_ip(std::to_string(rand() % 2));
		j->set_job_name(std::to_string(rand() % 2));
		j->set_restart_count(rand() % 100);
		j->set_containers_waiting(rand() % 100);
		j->set_status_ready(rand() % 100);
		j->set_requests_cpu_cores(rand() % 100);
		j->set_limits_cpu_cores(rand() % 100);
		j->set_requests_mem_bytes(rand() % 100);
		j->set_limits_mem_bytes(rand() % 100);
		j->set_restart_rate(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_controllers();
		generate_k8s_common(j->mutable_common());
		j->set_replicas_desired(rand() % 100);
		j->set_replicas_running(rand() % 100);
		j->set_replicas_fully_labeled(rand() % 100);
		j->set_replicas_ready(rand() % 100);
		j->set_replicas_available(rand() % 100);
		j->set_status_replicas(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_services();
		generate_k8s_common(j->mutable_common());
		j->set_cluster_ip(std::to_string(rand() % 2));
		j->add_ports();
		(*j->mutable_ports())[0].set_port(rand() % 2);
		(*j->mutable_ports())[0].set_target_port(rand() % 2);
		(*j->mutable_ports())[0].set_protocol(std::to_string(rand() % 2));
		(*j->mutable_ports())[0].set_node_port(rand() % 2);
		j->add_ports();
		(*j->mutable_ports())[1].set_port(rand() % 2);
		(*j->mutable_ports())[1].set_target_port(rand() % 2);
		(*j->mutable_ports())[1].set_protocol(std::to_string(rand() % 2));
		(*j->mutable_ports())[1].set_node_port(rand() % 2);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_replica_sets();
		generate_k8s_common(j->mutable_common());
		j->set_replicas_desired(rand() % 100);
		j->set_replicas_running(rand() % 100);
		j->set_replicas_fully_labeled(rand() % 100);
		j->set_replicas_ready(rand() % 100);
		j->set_replicas_available(rand() % 100);
		j->set_status_replicas(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_deployments();
		generate_k8s_common(j->mutable_common());
		j->set_replicas_desired(rand() % 100);
		j->set_replicas_running(rand() % 100);
		j->set_replicas_available(rand() % 100);
		j->set_replicas_unavailable(rand() % 100);
		j->set_replicas_updated(rand() % 100);
		j->set_replicas_paused(rand() % 100);
		j->set_status_replicas(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_daemonsets();
		generate_k8s_common(j->mutable_common());
		j->set_current_scheduled(rand() % 100);
		j->set_desired_scheduled(rand() % 100);
		j->set_pods_misscheduled(rand() % 100);
		j->set_pods_ready(rand() % 100);
		j->set_pods_available(rand() % 100);
		j->set_pods_unavailable(rand() % 100);
		j->set_updated_scheduled(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_jobs();
		generate_k8s_common(j->mutable_common());
		j->set_parallelism(rand() % 100);
		j->set_completions(rand() % 100);
		j->set_status_active(rand() % 100);
		j->set_num_succeeded(rand() % 100);
		j->set_num_failed(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_statefulsets();
		generate_k8s_common(j->mutable_common());
		j->set_replicas(rand() % 100);
		j->set_status_replicas(rand() % 100);
		j->set_status_replicas_current(rand() % 100);
		j->set_status_replicas_ready(rand() % 100);
		j->set_status_replicas_updated(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_resourcequotas();
		generate_k8s_common(j->mutable_common());
		j->set_limits_cpu_hard(rand() % 100);
		j->set_limits_memory_hard(rand() % 100);
		j->set_requests_cpu_hard(rand() % 100);
		j->set_requests_memory_hard(rand() % 100);
		j->set_limits_cpu_used(rand() % 100);
		j->set_limits_memory_used(rand() % 100);
		j->set_requests_cpu_used(rand() % 100);
		j->set_requests_memory_used(rand() % 100);
		j->set_double_limits_cpu_hard(rand() % 100);
		j->set_double_request_cpu_hard(rand() % 100);
		j->set_double_limits_cpu_used(rand() % 100);
		j->set_double_request_cpu_used(rand() % 100);
		j->set_requests_storage_hard(rand() % 100);
		j->set_configmaps_hard(rand() % 100);
		j->set_persistentvolumeclaims_hard(rand() % 100);
		j->set_pods_hard(rand() % 100);
		j->set_replicationcontrollers_hard(rand() % 100);
		j->set_resourcequotas_hard(rand() % 100);
		j->set_services_hard(rand() % 100);
		j->set_services_loadbalancers_hard(rand() % 100);
		j->set_services_nodeports_hard(rand() % 100);
		j->set_secrets_hard(rand() % 100);
		j->set_configmaps_used(rand() % 100);
		j->set_persistentvolumeclaims_used(rand() % 100);
		j->set_pods_used(rand() % 100);
		j->set_replicationcontrollers_used(rand() % 100);
		j->set_resourcequotas_used(rand() % 100);
		j->set_services_used(rand() % 100);
		j->set_services_loadbalancers_used(rand() % 100);
		j->set_services_nodeports_used(rand() % 100);
		j->set_secrets_used(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_persistentvolumes();
		generate_k8s_common(j->mutable_common());
		j->set_storage(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_persistentvolumeclaims();
		generate_k8s_common(j->mutable_common());
		j->set_storage(rand() % 100);
	}
	for (auto i = 0; i < 10; i++)
	{
		auto j = input->add_hpas();
		generate_k8s_common(j->mutable_common());
		j->set_replicas_min(rand() % 100);
		j->set_replicas_max(rand() % 100);
		j->set_replicas_current(rand() % 100);
		j->set_replicas_desired(rand() % 100);
	}
}

void generate_counter_time_bytes(draiosproto::counter_time_bytes* input)
{
	input->set_time_ns_in(rand() % 100);
	input->set_time_ns_out(rand() % 100);
	input->set_time_ns_other(rand() % 100);
	input->set_count_in(rand() % 100);
	input->set_count_out(rand() % 100);
	input->set_count_other(rand() % 100);
	input->set_bytes_in(rand() % 100);
	input->set_bytes_out(rand() % 100);
	input->set_bytes_other(rand() % 100);
	input->set_time_percentage_in(rand() % 100);
	input->set_time_percentage_out(rand() % 100);
	input->set_time_percentage_other(rand() % 100);
}

void generate_time_categories(draiosproto::time_categories* input)
{
	input->mutable_unknown()->set_count(rand() % 100);
	input->mutable_unknown()->set_time_ns(rand() % 100);
	input->mutable_unknown()->set_time_percentage(rand() % 100);
	input->mutable_other()->set_count(rand() % 100);
	input->mutable_other()->set_time_ns(rand() % 100);
	input->mutable_other()->set_time_percentage(rand() % 100);
	input->mutable_file()->set_count(rand() % 100);
	input->mutable_file()->set_time_ns(rand() % 100);
	input->mutable_file()->set_time_percentage(rand() % 100);
	input->mutable_net()->set_count(rand() % 100);
	input->mutable_net()->set_time_ns(rand() % 100);
	input->mutable_net()->set_time_percentage(rand() % 100);
	input->mutable_ipc()->set_count(rand() % 100);
	input->mutable_ipc()->set_time_ns(rand() % 100);
	input->mutable_ipc()->set_time_percentage(rand() % 100);
	input->mutable_memory()->set_count(rand() % 100);
	input->mutable_memory()->set_time_ns(rand() % 100);
	input->mutable_memory()->set_time_percentage(rand() % 100);
	input->mutable_process()->set_count(rand() % 100);
	input->mutable_process()->set_time_ns(rand() % 100);
	input->mutable_process()->set_time_percentage(rand() % 100);
	input->mutable_sleep()->set_count(rand() % 100);
	input->mutable_sleep()->set_time_ns(rand() % 100);
	input->mutable_sleep()->set_time_percentage(rand() % 100);
	input->mutable_system()->set_count(rand() % 100);
	input->mutable_system()->set_time_ns(rand() % 100);
	input->mutable_system()->set_time_percentage(rand() % 100);
	input->mutable_signal()->set_count(rand() % 100);
	input->mutable_signal()->set_time_ns(rand() % 100);
	input->mutable_signal()->set_time_percentage(rand() % 100);
	input->mutable_user()->set_count(rand() % 100);
	input->mutable_user()->set_time_ns(rand() % 100);
	input->mutable_user()->set_time_percentage(rand() % 100);
	input->mutable_time()->set_count(rand() % 100);
	input->mutable_time()->set_time_ns(rand() % 100);
	input->mutable_time()->set_time_percentage(rand() % 100);
	input->mutable_wait()->set_count(rand() % 100);
	input->mutable_wait()->set_time_ns(rand() % 100);
	input->mutable_wait()->set_time_percentage(rand() % 100);
	input->mutable_processing()->set_count(rand() % 100);
	input->mutable_processing()->set_time_ns(rand() % 100);
	input->mutable_processing()->set_time_percentage(rand() % 100);
	generate_counter_time_bytes(input->mutable_io_file());
	generate_counter_time_bytes(input->mutable_io_net());
	generate_counter_time_bytes(input->mutable_io_other());
}

void generate_counter_time_bidirectional(draiosproto::counter_time_bidirectional* input)
{
	input->set_count_in(rand() % 100);
	input->set_count_out(rand() % 100);
	input->set_time_ns_in(rand() % 100);
	input->set_time_ns_out(rand() % 100);
}

void generate_resource_categories(draiosproto::resource_categories* input)
{
	input->set_capacity_score(rand() % 100);
	input->set_stolen_capacity_score(rand() % 100);
	input->set_connection_queue_usage_pct(rand() % 100);
	input->set_fd_usage_pct(rand() % 100);
	input->set_cpu_pct(rand() % 100);
	input->set_resident_memory_usage_kb(rand() % 100);
	input->set_virtual_memory_usage_kb(rand() % 100);
	input->set_swap_memory_usage_kb(rand() % 100);
	input->set_major_pagefaults(rand() % 100);
	input->set_minor_pagefaults(rand() % 100);
	input->set_fd_count(rand() % 100);
	input->set_cpu_shares(rand() % 100);
	input->set_cpu_shares_usage_pct(rand() % 100);
	input->set_memory_limit_kb(rand() % 100);
	input->set_swap_limit_kb(rand() % 100);
	input->set_cpu_quota_used_pct(rand() % 100);
	input->set_swap_memory_total_kb(rand() % 100);
	input->set_swap_memory_available_kb(rand() % 100);
	input->set_count_processes(rand() % 100);
	input->set_proc_start_count(rand() % 100);
	input->set_jmx_sent(rand() % 100);
	input->set_jmx_total(rand() % 100);
	input->set_statsd_sent(rand() % 100);
	input->set_statsd_total(rand() % 100);
	input->set_app_checks_sent(rand() % 100);
	input->set_app_checks_total(rand() % 100);
	input->set_threads_count(rand() % 100);
	input->set_prometheus_sent(rand() % 100);
	input->set_prometheus_total(rand() % 100);
}

void generate_counter_syscall_errors(draiosproto::counter_syscall_errors* input)
{
	input->set_count(rand() % 100);
	input->add_top_error_codes(rand() % 100);
	input->add_top_error_codes(rand() % 100);
	input->set_count_file(rand() % 100);
	input->set_count_file_open(rand() % 100);
	input->set_count_net(rand() % 100);
}

void generate_transaction_breakdown_categories(draiosproto::transaction_breakdown_categories* input)
{
	input->mutable_other()->set_count(rand() % 100);
	input->mutable_other()->set_time_ns(rand() % 100);
	input->mutable_other()->set_time_percentage(rand() % 100);
	generate_counter_time_bytes(input->mutable_io_file());
	generate_counter_time_bytes(input->mutable_io_net());
	input->mutable_processing()->set_count(rand() % 100);
	input->mutable_processing()->set_time_ns(rand() % 100);
	input->mutable_processing()->set_time_percentage(rand() % 100);
}

void generate_connection_categories(draiosproto::connection_categories* input)
{
	input->mutable_server()->set_count_in(rand() % 100);
	input->mutable_server()->set_count_out(rand() % 100);
	input->mutable_server()->set_bytes_in(rand() % 100);
	input->mutable_server()->set_bytes_out(rand() % 100);
	generate_counter_time_bidirectional(input->mutable_transaction_counters());
	input->set_n_aggregated_connections(rand() % 100);
	generate_counter_time_bidirectional(input->mutable_max_transaction_counters());
	input->mutable_client()->set_count_in(rand() % 100);
	input->mutable_client()->set_count_out(rand() % 100);
	input->mutable_client()->set_bytes_in(rand() % 100);
	input->mutable_client()->set_bytes_out(rand() % 100);
}

void generate_counter_proto_entry(draiosproto::counter_proto_entry* input)
{
	input->set_ncalls(rand() % 100);
	input->set_time_tot(rand() % 100);
	input->set_time_max(rand() % 100);
	input->set_bytes_in(rand() % 100);
	input->set_bytes_out(rand() % 100);
	input->set_nerrors(rand() % 100);
}

void generate_proto_info(draiosproto::proto_info* input, std::string in_name = "asdlkjf;aklj")
{
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_http()->add_server_urls();
		(*input->mutable_http()->mutable_server_urls())[i].set_url(std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_http()->mutable_server_urls())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_http()->add_client_urls();
		(*input->mutable_http()->mutable_client_urls())[i].set_url(std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_http()->mutable_client_urls())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_http()->add_client_status_codes();
		(*input->mutable_http()->mutable_client_status_codes())[i].set_status_code(rand() % 2);
		(*input->mutable_http()->mutable_client_status_codes())[i].set_ncalls(rand() % 100);
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_http()->add_server_status_codes();
		(*input->mutable_http()->mutable_server_status_codes())[i].set_status_code(rand() % 2);
		(*input->mutable_http()->mutable_server_status_codes())[i].set_ncalls(rand() % 100);
	}
	generate_counter_proto_entry(input->mutable_http()->mutable_server_totals());
	generate_counter_proto_entry(input->mutable_http()->mutable_client_totals());

	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mysql()->add_server_queries();
		(*input->mutable_mysql()->mutable_server_queries())[i].set_name(std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_mysql()->mutable_server_queries())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mysql()->add_client_queries();
		(*input->mutable_mysql()->mutable_client_queries())[i].set_name(std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_mysql()->mutable_client_queries())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mysql()->add_server_query_types();
		(*input->mutable_mysql()->mutable_server_query_types())[i].set_type(
		    (draiosproto::sql_statement_type)(1 + (rand() % 10)));
		generate_counter_proto_entry(
		    (*input->mutable_mysql()->mutable_server_query_types())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mysql()->add_client_query_types();
		(*input->mutable_mysql()->mutable_client_query_types())[i].set_type(
		    (draiosproto::sql_statement_type)(1 + (rand() % 10)));
		generate_counter_proto_entry(
		    (*input->mutable_mysql()->mutable_client_query_types())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mysql()->add_server_tables();
		(*input->mutable_mysql()->mutable_server_tables())[i].set_name(std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_mysql()->mutable_server_tables())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mysql()->add_client_tables();
		(*input->mutable_mysql()->mutable_client_tables())[i].set_name(std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_mysql()->mutable_client_tables())[i].mutable_counters());
	}
	generate_counter_proto_entry(input->mutable_mysql()->mutable_server_totals());
	generate_counter_proto_entry(input->mutable_mysql()->mutable_client_totals());

	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_postgres()->add_server_queries();
		(*input->mutable_postgres()->mutable_server_queries())[i].set_name(
		    std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_postgres()->mutable_server_queries())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_postgres()->add_client_queries();
		(*input->mutable_postgres()->mutable_client_queries())[i].set_name(
		    std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_postgres()->mutable_client_queries())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_postgres()->add_server_query_types();
		(*input->mutable_postgres()->mutable_server_query_types())[i].set_type(
		    (draiosproto::sql_statement_type)(1 + (rand() % 10)));
		generate_counter_proto_entry(
		    (*input->mutable_postgres()->mutable_server_query_types())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_postgres()->add_client_query_types();
		(*input->mutable_postgres()->mutable_client_query_types())[i].set_type(
		    (draiosproto::sql_statement_type)(1 + (rand() % 10)));
		generate_counter_proto_entry(
		    (*input->mutable_postgres()->mutable_client_query_types())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_postgres()->add_server_tables();
		(*input->mutable_postgres()->mutable_server_tables())[i].set_name(
		    std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_postgres()->mutable_server_tables())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_postgres()->add_client_tables();
		(*input->mutable_postgres()->mutable_client_tables())[i].set_name(
		    std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_postgres()->mutable_client_tables())[i].mutable_counters());
	}
	generate_counter_proto_entry(input->mutable_postgres()->mutable_server_totals());
	generate_counter_proto_entry(input->mutable_postgres()->mutable_client_totals());

	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mongodb()->add_servers_ops();
		(*input->mutable_mongodb()->mutable_servers_ops())[i].set_op(
		    (draiosproto::mongodb_op_type)(1 + (rand() % 10)));
		generate_counter_proto_entry(
		    (*input->mutable_mongodb()->mutable_servers_ops())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mongodb()->add_client_ops();
		(*input->mutable_mongodb()->mutable_client_ops())[i].set_op(
		    (draiosproto::mongodb_op_type)(1 + (rand() % 10)));
		generate_counter_proto_entry(
		    (*input->mutable_mongodb()->mutable_client_ops())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mongodb()->add_server_collections();
		(*input->mutable_mongodb()->mutable_server_collections())[i].set_name(
		    std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_mongodb()->mutable_server_collections())[i].mutable_counters());
	}
	for (uint32_t i = 0; i < 15; i++)
	{
		input->mutable_mongodb()->add_client_collections();
		(*input->mutable_mongodb()->mutable_client_collections())[i].set_name(
		    std::to_string(rand() % 2));
		generate_counter_proto_entry(
		    (*input->mutable_mongodb()->mutable_client_collections())[i].mutable_counters());
	}
	generate_counter_proto_entry(input->mutable_mongodb()->mutable_server_totals());
	generate_counter_proto_entry(input->mutable_mongodb()->mutable_client_totals());

	input->mutable_java()->set_process_name(in_name);
	for (uint32_t i = 0; i < 10; i++)
	{
		input->mutable_java()->add_beans();
		(*input->mutable_java()->mutable_beans())[i].set_name(std::to_string(rand() % 2));
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_java()->mutable_beans())[i].add_attributes();
			(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j].set_name(
			    std::to_string(j % 2));
			(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j].set_value(
			    rand() % 100);
			for (uint32_t k = 0; k < 10 && j != 0;
			     k++)  // BE does different stuff depending on subattribute count
			{
				(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j]
				    .add_subattributes();
				(*(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j]
				      .mutable_subattributes())[k]
				    .set_name(std::to_string(rand() % 2));
				(*(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j]
				      .mutable_subattributes())[k]
				    .set_value(rand() % 100);
			}
			(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j].set_alias(
			    std::to_string(j % 2));
			(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j].set_type(
			    (draiosproto::jmx_metric_type)(1 + (j % 2)));
			(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j].set_unit(
			    (draiosproto::unit)(j % 4));
			(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j].set_scale(
			    (draiosproto::scale)(j % 10));
			for (uint32_t k = 0; k < 5; k++)
			{
				(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j]
				    .add_segment_by();
				(*(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j]
				      .mutable_segment_by())[k]
				    .set_key(std::to_string(10 * k + (rand() % 2)));
				(*(*(*input->mutable_java()->mutable_beans())[i].mutable_attributes())[j]
				      .mutable_segment_by())[k]
				    .set_value(std::to_string(rand() % 2));
			}
		}
	}

	for (int i = 0; i < 80; i++)
	{
		// we very carefully construct the statsd metrics so that if the metrics collide,
		// they must have the same type. We do this by setting the type to i % 4, and setting
		// the elements of the primary key to be a given range for that type.
		input->mutable_statsd()->add_statsd_metrics();
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_name(
		    std::to_string(10 * (i % 4) + (rand() % 2)));
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].add_tags()->set_key(
		    std::to_string(10 * (i % 4) + (rand() % 2)));
		(*(*input->mutable_statsd()->mutable_statsd_metrics())[i].mutable_tags())[0].set_value(
		    std::to_string(10 * (i % 4) + (rand() % 2)));
		// have to add some since BE doesn't really deal with duplicate keys SMAGENT-2069
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].add_tags()->set_key(
		    std::to_string(10 * (i % 4) + 2 + (rand() % 2)));
		(*(*input->mutable_statsd()->mutable_statsd_metrics())[i].mutable_tags())[1].set_value(
		    std::to_string(10 * (i % 4) + (rand() % 2)));
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_type(
		    (draiosproto::statsd_metric_type)(1 + (i % 4)));
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_value(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_sum(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_min(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_max(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_count(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_median(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_percentile_95(rand() % 2);
		(*input->mutable_statsd()->mutable_statsd_metrics())[i].set_percentile_99(rand() % 2);
	}

	input->mutable_app()->set_process_name("klnsdfvhjh");
	for (uint32_t i = 0; i < 50; i++)
	{
		input->mutable_app()->add_metrics();
		(*input->mutable_app()->mutable_metrics())[i].set_name(std::to_string(10 * i));
		(*input->mutable_app()->mutable_metrics())[i].set_type(
		    (draiosproto::app_metric_type)(1 + (i % 2)));
		(*input->mutable_app()->mutable_metrics())[i].set_value(rand() % 100);
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_app()->mutable_metrics())[i].add_tags();
			(*(*input->mutable_app()->mutable_metrics())[i].mutable_tags())[j].set_key(
			    std::to_string(100 * j + (i % 2)));
			(*(*input->mutable_app()->mutable_metrics())[i].mutable_tags())[j].set_value(
			    std::to_string(i % 2));
		}
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_app()->mutable_metrics())[i].add_buckets();
			(*(*input->mutable_app()->mutable_metrics())[i].mutable_buckets())[j].set_label(
			    std::to_string(rand() % 2));
			(*(*input->mutable_app()->mutable_metrics())[i].mutable_buckets())[j].set_count(rand() %
			                                                                                100);
		}
		(*input->mutable_app()->mutable_metrics())[i].set_prometheus_type(
		    (draiosproto::prometheus_type)(rand() % 6));
	}
	for (uint32_t i = 0; i < 50; i++)
	{
		input->mutable_app()->add_checks();
		(*input->mutable_app()->mutable_checks())[i].set_name(std::to_string(10 * i));
		(*input->mutable_app()->mutable_checks())[i].set_value(
		    (draiosproto::app_check_value)(rand() % 2));
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_app()->mutable_checks())[i].add_tags();
			(*(*input->mutable_app()->mutable_checks())[i].mutable_tags())[j].set_key(
			    std::to_string(10 * j + (i % 2)));
			(*(*input->mutable_app()->mutable_checks())[i].mutable_tags())[j].set_value(
			    std::to_string(i % 2));
		}
	}

	input->mutable_prometheus()->set_process_name("agsedrfijnou;hawerjkln;.hb");
	for (uint32_t i = 0; i < 50; i++)
	{
		input->mutable_prometheus()->add_metrics();
		(*input->mutable_prometheus()->mutable_metrics())[i].set_name(std::to_string(rand() % 2));
		(*input->mutable_prometheus()->mutable_metrics())[i].set_type(
		    (draiosproto::app_metric_type)(1 + (rand() % 2)));
		(*input->mutable_prometheus()->mutable_metrics())[i].set_value(rand() % 100);
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_prometheus()->mutable_metrics())[i].add_tags();
			(*(*input->mutable_prometheus()->mutable_metrics())[i].mutable_tags())[j].set_key(
			    std::to_string(10 * j + (rand() % 2)));
			(*(*input->mutable_prometheus()->mutable_metrics())[i].mutable_tags())[j].set_value(
			    std::to_string(rand() % 2));
		}
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_prometheus()->mutable_metrics())[i].add_buckets();
			(*(*input->mutable_prometheus()->mutable_metrics())[i].mutable_buckets())[j].set_label(
			    std::to_string(rand() % 2));
			(*(*input->mutable_prometheus()->mutable_metrics())[i].mutable_buckets())[j].set_count(
			    rand() % 100);
		}
		(*input->mutable_prometheus()->mutable_metrics())[i].set_prometheus_type(
		    (draiosproto::prometheus_type)(rand() % 6));
	}
	for (uint32_t i = 0; i < 50; i++)
	{
		input->mutable_prometheus()->add_checks();
		(*input->mutable_prometheus()->mutable_checks())[i].set_name(std::to_string(rand() % 2));
		(*input->mutable_prometheus()->mutable_checks())[i].set_value(
		    (draiosproto::app_check_value)(rand() % 2));
		for (uint32_t j = 0; j < 10; j++)
		{
			(*input->mutable_prometheus()->mutable_checks())[i].add_tags();
			(*(*input->mutable_prometheus()->mutable_checks())[i].mutable_tags())[j].set_key(
			    std::to_string(10 * j + (rand() % 2)));
			(*(*input->mutable_prometheus()->mutable_checks())[i].mutable_tags())[j].set_value(
			    std::to_string(rand() % 2));
		}
	}
}

void generate_marathon_group(draiosproto::marathon_group* input)
{
	input->set_id(std::to_string(rand() % 3));
	for (int i = 0; i < 4; i++)
	{
		input->add_apps();
		(*input->mutable_apps())[i].set_id(std::to_string(rand() % 2));
		for (int j = 0; j < 2; j++)
		{
			(*input->mutable_apps())[i].add_task_ids(std::to_string(rand() % 2));
		}
	}
	for (int i = 0; i < 2; i++)
	{
		input->add_groups()->set_id(std::to_string(rand() % 2));
	}
}

void generate_mesos_common(draiosproto::mesos_common* input)
{
	input->set_uid(std::to_string(rand() % 2));
	input->set_name(std::to_string(rand() % 2));
	for (int i = 0; i <= rand() % 2; i++)
	{
		input->add_labels()->set_key(std::to_string(10 * i + (rand() % 2)));
		(*input->mutable_labels())[i].set_value(std::to_string(rand() % 2));
	}
}
void generate_swarm_common(draiosproto::swarm_common* input)
{
	input->set_id(std::to_string(rand() % 2));
	input->set_name(std::to_string(rand() % 2));
	for (int i = 0; i <= rand() % 2; i++)
	{
		input->add_labels()->set_key(std::to_string(10 * i + (rand() % 2)));
		(*input->mutable_labels())[i].set_value(std::to_string(rand() % 2));
	}
}

TEST(aggregator_extra, DISABLED_generate)
{
	for (int loop_count = 0; loop_count < 10; loop_count++)
	{
		draiosproto::metrics input;
		input.set_machine_id("asdlkfj");
		input.set_customer_id("20udasfi");
		input.set_timestamp_ns((uint64_t)1000000000 * loop_count);

		// generate some host stuff
		input.mutable_hostinfo()->set_hostname("290sdiaf");
		input.mutable_hostinfo()->set_num_cpus(rand() % 100);
		input.mutable_hostinfo()->add_cpu_loads(rand() % 100);
		input.mutable_hostinfo()->add_cpu_loads(rand() % 100);
		input.mutable_hostinfo()->add_cpu_loads(rand() % 100);
		input.mutable_hostinfo()->set_physical_memory_size_bytes(rand() % 100);
		generate_time_categories(input.mutable_hostinfo()->mutable_tcounters());
		generate_counter_time_bidirectional(
		    input.mutable_hostinfo()->mutable_transaction_counters());
		input.mutable_hostinfo()->set_transaction_processing_delay(rand() % 100);
		generate_resource_categories(input.mutable_hostinfo()->mutable_resource_counters());
		generate_counter_syscall_errors(input.mutable_hostinfo()->mutable_syscall_errors());
		generate_counter_time_bytes(input.mutable_hostinfo()->mutable_external_io_net());
		input.mutable_hostinfo()->add_cpu_steal(rand() % 100);
		input.mutable_hostinfo()->add_cpu_steal(rand() % 100);
		input.mutable_hostinfo()->add_cpu_steal(rand() % 100);
		generate_transaction_breakdown_categories(input.mutable_hostinfo()->mutable_reqcounters());
		input.mutable_hostinfo()->set_next_tiers_delay(rand() % 100);
		generate_counter_time_bidirectional(
		    input.mutable_hostinfo()->mutable_max_transaction_counters());
		input.mutable_hostinfo()->add_network_by_serverports()->set_port(234);
		generate_connection_categories(
		    (*input.mutable_hostinfo()->mutable_network_by_serverports())[0].mutable_counters());
		for (int i = 1; i < 5; i++)
		{  // get some repeats
			input.mutable_hostinfo()->add_network_by_serverports()->set_port(rand() % 2);
			generate_connection_categories(
			    (*input.mutable_hostinfo()->mutable_network_by_serverports())[i]
			        .mutable_counters());
		}
		input.mutable_hostinfo()->add_cpu_idle(rand() % 100);
		input.mutable_hostinfo()->add_cpu_idle(rand() % 100);
		input.mutable_hostinfo()->add_cpu_idle(rand() % 100);
		input.mutable_hostinfo()->set_system_load(rand() % 100);
		input.mutable_hostinfo()->set_uptime(rand() % 100);
		input.mutable_hostinfo()->add_system_cpu(rand() % 100);
		input.mutable_hostinfo()->add_system_cpu(rand() % 100);
		input.mutable_hostinfo()->add_system_cpu(rand() % 100);
		input.mutable_hostinfo()->add_user_cpu(rand() % 100);
		input.mutable_hostinfo()->add_user_cpu(rand() % 100);
		input.mutable_hostinfo()->add_user_cpu(rand() % 100);
		input.mutable_hostinfo()->set_memory_bytes_available_kb(rand() % 100);
		input.mutable_hostinfo()->add_iowait_cpu(rand() % 100);
		input.mutable_hostinfo()->add_iowait_cpu(rand() % 100);
		input.mutable_hostinfo()->add_iowait_cpu(rand() % 100);
		input.mutable_hostinfo()->add_nice_cpu(rand() % 100);
		input.mutable_hostinfo()->add_nice_cpu(rand() % 100);
		input.mutable_hostinfo()->add_nice_cpu(rand() % 100);
		input.mutable_hostinfo()->set_system_load_1(rand() % 100);
		input.mutable_hostinfo()->set_system_load_5(rand() % 100);
		input.mutable_hostinfo()->set_system_load_15(rand() % 100);

		// generate some connections
		input.add_ipv4_connections()->mutable_tuple()->set_sip(2340);
		(*input.mutable_ipv4_connections())[0].mutable_tuple()->set_dip(487);
		(*input.mutable_ipv4_connections())[0].mutable_tuple()->set_sport(3);
		(*input.mutable_ipv4_connections())[0].mutable_tuple()->set_dport(94);
		(*input.mutable_ipv4_connections())[0].mutable_tuple()->set_l4proto(2098);
		(*input.mutable_ipv4_connections())[0].set_spid(984);
		(*input.mutable_ipv4_connections())[0].set_dpid(884);
		generate_connection_categories((*input.mutable_ipv4_connections())[0].mutable_counters());
		(*input.mutable_ipv4_connections())[0].set_state(
		    (draiosproto::connection_state)(rand() % 3));
		(*input.mutable_ipv4_connections())[0].set_error_code(
		    (draiosproto::error_code)(1 + (rand() % 100)));

		for (int i = 1; i < 130; i++)  // guaranteed to get some repeats
		{
			input.add_ipv4_connections()->mutable_tuple()->set_sip(rand() % 2);
			(*input.mutable_ipv4_connections())[i].mutable_tuple()->set_dip(rand() % 2);
			(*input.mutable_ipv4_connections())[i].mutable_tuple()->set_sport(rand() % 2);
			(*input.mutable_ipv4_connections())[i].mutable_tuple()->set_dport(rand() % 2);
			(*input.mutable_ipv4_connections())[i].mutable_tuple()->set_l4proto(rand() % 2);
			(*input.mutable_ipv4_connections())[i].set_spid(rand() % 2);
			(*input.mutable_ipv4_connections())[i].set_dpid(rand() % 2);
			generate_connection_categories(
			    (*input.mutable_ipv4_connections())[i].mutable_counters());
			(*input.mutable_ipv4_connections())[i].set_state(
			    (draiosproto::connection_state)(rand() % 3));
			(*input.mutable_ipv4_connections())[i].set_error_code(
			    (draiosproto::error_code)(1 + (rand() % 100)));
		}

		// generate some interfaces
		input.add_ipv4_network_interfaces()->set_name("asd2389");
		(*input.mutable_ipv4_network_interfaces())[0].set_addr(9129);
		(*input.mutable_ipv4_network_interfaces())[0].set_netmask(20);
		(*input.mutable_ipv4_network_interfaces())[0].set_bcast(1308);

		for (int i = 1; i < 10; i++)
		{
			input.add_ipv4_network_interfaces()->set_name(std::to_string(rand() % 2));
			(*input.mutable_ipv4_network_interfaces())[i].set_addr(rand() % 2);
			(*input.mutable_ipv4_network_interfaces())[i].set_netmask(rand() % 2);
			(*input.mutable_ipv4_network_interfaces())[i].set_bcast(rand() % 2);
		}

		// generate some programs
		input.add_programs()->mutable_procinfo()->mutable_details()->set_comm("23");
		(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->set_exe("9o wser");
		(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->set_container_id(
		    "2039u asdjf");
		(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->add_args("jjff");
		(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->add_args("jjff");
		(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->add_args(
		    "jjfilskdjf");
		generate_time_categories(
		    (*input.mutable_programs())[0].mutable_procinfo()->mutable_tcounters());
		(*input.mutable_programs())[0].mutable_procinfo()->set_transaction_processing_delay(rand() %
		                                                                                    100);
		generate_resource_categories(
		    (*input.mutable_programs())[0].mutable_procinfo()->mutable_resource_counters());
		generate_counter_syscall_errors(
		    (*input.mutable_programs())[0].mutable_procinfo()->mutable_syscall_errors());
		(*input.mutable_programs())[0].mutable_procinfo()->set_next_tiers_delay(rand() % 100);
		(*input.mutable_programs())[0].mutable_procinfo()->set_netrole(rand() % 100);
		generate_counter_time_bidirectional(
		    (*input.mutable_programs())[0].mutable_procinfo()->mutable_max_transaction_counters());
		generate_proto_info((*input.mutable_programs())[0].mutable_procinfo()->mutable_protos(),
		                    "j" + input.programs()[0].procinfo().details().comm());
		(*input.mutable_programs())[0].mutable_procinfo()->set_start_count(rand() % 100);
		(*input.mutable_programs())[0].mutable_procinfo()->set_count_processes(rand() % 100);
		(*input.mutable_programs())[0].mutable_procinfo()->add_top_files()->set_name("a8");
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[0].set_bytes(
		    rand() % 100);
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[0].set_time_ns(
		    rand() % 100);
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[0].set_open_count(
		    rand() % 100);
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[0].set_errors(
		    rand() % 100);
		for (int i = 1; i < 5; i++)
		{
			(*input.mutable_programs())[0].mutable_procinfo()->add_top_files()->set_name(
			    std::to_string(rand() % 2));
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[i].set_bytes(
			    rand() % 100);
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[i]
			    .set_time_ns(rand() % 100);
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[i]
			    .set_open_count(rand() % 100);
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_files())[i].set_errors(
			    rand() % 100);
		}
		(*input.mutable_programs())[0].mutable_procinfo()->add_top_devices()->set_name("02w3894u");
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[0].set_bytes(
		    rand() % 100);
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[0].set_time_ns(
		    rand() % 100);
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[0]
		    .set_open_count(rand() % 100);
		(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[0].set_errors(
		    rand() % 100);
		for (int i = 1; i < 5; i++)
		{
			(*input.mutable_programs())[0].mutable_procinfo()->add_top_devices()->set_name(
			    std::to_string(rand() % 2));
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[i]
			    .set_bytes(rand() % 100);
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[i]
			    .set_time_ns(rand() % 100);
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[i]
			    .set_open_count(rand() % 100);
			(*(*input.mutable_programs())[0].mutable_procinfo()->mutable_top_devices())[i]
			    .set_errors(rand() % 100);
		}
		(*input.mutable_programs())[0].add_pids(23409);
		(*input.mutable_programs())[0].add_pids(230948);
		(*input.mutable_programs())[0].add_uids(209);
		(*input.mutable_programs())[0].add_uids(1234);
		(*input.mutable_programs())[0].set_environment_hash("209fjs");
		(*input.mutable_programs())[0].add_program_reporting_group_id(59823);
		(*input.mutable_programs())[0].add_program_reporting_group_id(90298);

		for (int j = 1; j < 5; j++)
		{
			// need to use big values for these things since BE has hash collissions
			input.add_programs()->mutable_procinfo()->mutable_details()->set_comm(
			    std::to_string(j));
			(*input.mutable_programs())[j].mutable_procinfo()->mutable_details()->set_exe(
			    std::to_string(10 * j));
			(*input.mutable_programs())[j].mutable_procinfo()->mutable_details()->set_container_id(
			    std::to_string(100 * j));
			(*input.mutable_programs())[j].mutable_procinfo()->mutable_details()->add_args(
			    std::to_string(1000 * j));
			generate_time_categories(
			    (*input.mutable_programs())[j].mutable_procinfo()->mutable_tcounters());
			(*input.mutable_programs())[j].mutable_procinfo()->set_transaction_processing_delay(
			    rand() % 100);
			generate_resource_categories(
			    (*input.mutable_programs())[j].mutable_procinfo()->mutable_resource_counters());
			generate_counter_syscall_errors(
			    (*input.mutable_programs())[j].mutable_procinfo()->mutable_syscall_errors());
			(*input.mutable_programs())[j].mutable_procinfo()->set_next_tiers_delay(rand() % 100);
			(*input.mutable_programs())[j].mutable_procinfo()->set_netrole(rand() % 100);
			generate_counter_time_bidirectional((*input.mutable_programs())[j]
			                                        .mutable_procinfo()
			                                        ->mutable_max_transaction_counters());
			generate_proto_info((*input.mutable_programs())[j].mutable_procinfo()->mutable_protos(),
			                    "j" + input.programs()[j].procinfo().details().comm());
			(*input.mutable_programs())[j].mutable_procinfo()->set_start_count(rand() % 100);
			(*input.mutable_programs())[j].mutable_procinfo()->set_count_processes(rand() % 100);
			(*input.mutable_programs())[j].mutable_procinfo()->add_top_files()->set_name("a8");
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[0].set_bytes(
			    rand() % 100);
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[0]
			    .set_time_ns(rand() % 100);
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[0]
			    .set_open_count(rand() % 100);
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[0].set_errors(
			    rand() % 100);
			for (int i = 1; i < 5; i++)
			{
				(*input.mutable_programs())[j].mutable_procinfo()->add_top_files()->set_name(
				    std::to_string(rand() % 2));
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[i]
				    .set_bytes(rand() % 100);
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[i]
				    .set_time_ns(rand() % 100);
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[i]
				    .set_open_count(rand() % 100);
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_files())[i]
				    .set_errors(rand() % 100);
			}
			(*input.mutable_programs())[j].mutable_procinfo()->add_top_devices()->set_name(
			    "02w3894u");
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[0]
			    .set_bytes(rand() % 100);
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[0]
			    .set_time_ns(rand() % 100);
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[0]
			    .set_open_count(rand() % 100);
			(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[0]
			    .set_errors(rand() % 100);
			for (int i = 1; i < 5; i++)
			{
				(*input.mutable_programs())[j].mutable_procinfo()->add_top_devices()->set_name(
				    std::to_string(rand() % 2));
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[i]
				    .set_bytes(rand() % 100);
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[i]
				    .set_time_ns(rand() % 100);
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[i]
				    .set_open_count(rand() % 100);
				(*(*input.mutable_programs())[j].mutable_procinfo()->mutable_top_devices())[i]
				    .set_errors(rand() % 100);
			}
			(*input.mutable_programs())[j].add_pids(j);  // don't want pid conflicts, or BE has
			// undefined behaviior
			(*input.mutable_programs())[j].add_pids(100 * j);
			(*input.mutable_programs())[j].add_pids(1000 * j);
			(*input.mutable_programs())[j].add_uids(rand() % 100);
			(*input.mutable_programs())[j].add_uids(rand() % 100);
			(*input.mutable_programs())[j].add_uids(rand() % 100);
			(*input.mutable_programs())[j].set_environment_hash(std::to_string(10000 * j));
			(*input.mutable_programs())[j].add_program_reporting_group_id(rand() % 100);
			(*input.mutable_programs())[j].add_program_reporting_group_id(rand() % 100);
			(*input.mutable_programs())[j].add_program_reporting_group_id(rand() % 100);
		}

		input.set_sampling_ratio(rand() % 100);
		input.set_host_custom_name("asd;df");
		input.set_host_tags("wlkekjfkljsd");
		input.set_version("woidej;sfd");

		// generate some mounts
		input.add_mounts()->set_device("123409f");
		(*input.mutable_mounts())[0].set_mount_dir("einput.add_mounts");
		(*input.mutable_mounts())[0].set_type("0uwsdoifj");
		(*input.mutable_mounts())[0].set_size_bytes(rand() % 100);
		(*input.mutable_mounts())[0].set_used_bytes(rand() % 100);
		(*input.mutable_mounts())[0].set_available_bytes(rand() % 100);
		(*input.mutable_mounts())[0].set_total_inodes(rand() % 100);
		(*input.mutable_mounts())[0].set_used_inodes(rand() % 100);

		for (int i = 1; i < 10; i++)
		{
			input.add_mounts()->set_device(std::to_string(rand() % 2));
			(*input.mutable_mounts())[i].set_mount_dir(std::to_string(rand() % 2));
			(*input.mutable_mounts())[i].set_type(std::to_string(rand() % 2));
			(*input.mutable_mounts())[i].set_size_bytes(rand() % 100);
			(*input.mutable_mounts())[i].set_used_bytes(rand() % 100);
			(*input.mutable_mounts())[i].set_available_bytes(rand() % 100);
			(*input.mutable_mounts())[i].set_total_inodes(rand() % 100);
			(*input.mutable_mounts())[i].set_used_inodes(rand() % 100);
		}

		// generate some files
		input.add_top_files()->set_name("w0asdiouf ");
		(*input.mutable_top_files())[0].set_bytes(rand() % 100);
		(*input.mutable_top_files())[0].set_time_ns(rand() % 100);
		(*input.mutable_top_files())[0].set_open_count(rand() % 100);
		(*input.mutable_top_files())[0].set_errors(rand() % 100);
		for (int i = 1; i < 5; i++)
		{
			input.add_top_files()->set_name(std::to_string(rand() % 2));
			(*input.mutable_top_files())[i].set_bytes(rand() % 100);
			(*input.mutable_top_files())[i].set_time_ns(rand() % 100);
			(*input.mutable_top_files())[i].set_open_count(rand() % 100);
			(*input.mutable_top_files())[i].set_errors(rand() % 100);
		}

		// geenrate some protos
		generate_proto_info(input.mutable_protos());

		input.set_instance_id("qaweiour2");

		// generate some k8s
		generate_k8s(input.mutable_kubernetes());
		generate_k8s(input.mutable_global_kubernetes());

		// generate some containers
		input.add_containers()->set_id("0sadfoi2");
		(*input.mutable_containers())[0].set_type((draiosproto::container_type)3);
		(*input.mutable_containers())[0].set_name("089uasdf");
		(*input.mutable_containers())[0].set_image("209f");
		generate_time_categories((*input.mutable_containers())[0].mutable_tcounters());
		generate_transaction_breakdown_categories(
		    (*input.mutable_containers())[0].mutable_reqcounters());
		generate_counter_time_bidirectional(
		    (*input.mutable_containers())[0].mutable_transaction_counters());
		generate_counter_time_bidirectional(
		    (*input.mutable_containers())[0].mutable_max_transaction_counters());
		(*input.mutable_containers())[0].set_transaction_processing_delay(rand() % 100);
		(*input.mutable_containers())[0].set_next_tiers_delay(rand() % 100);
		generate_resource_categories((*input.mutable_containers())[0].mutable_resource_counters());
		generate_counter_syscall_errors((*input.mutable_containers())[0].mutable_syscall_errors());
		for (int i = 0; i < 10; i++)
		{
			(*input.mutable_containers())[0].add_port_mappings()->set_host_ip(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_port_mappings())[i].set_host_port(rand() %
			                                                                             2);
			(*(*input.mutable_containers())[0].mutable_port_mappings())[i].set_container_ip(rand() %
			                                                                                2);
			(*(*input.mutable_containers())[0].mutable_port_mappings())[i].set_container_port(
			    rand() % 2);
		}
		generate_proto_info((*input.mutable_containers())[0].mutable_protos());
		for (int i = 0; i < 5; i++)
		{
			(*input.mutable_containers())[0].add_labels()->set_key(
			    std::to_string(10 * i + (rand() % 2)));
			(*(*input.mutable_containers())[0].mutable_labels())[i].set_value(
			    std::to_string(rand() % 2));
		}
		(*input.mutable_containers())[0].add_mounts()->set_device("asdf09u");
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_mount_dir(
		    "e(*input.mutable_containers())[0].add_mounts");
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_type("0uwsdoifj");
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_size_bytes(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_used_bytes(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_available_bytes(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_total_inodes(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_mounts())[0].set_used_inodes(rand() % 100);

		for (int i = 1; i < 10; i++)
		{
			(*input.mutable_containers())[0].add_mounts()->set_device(std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_mount_dir(
			    std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_type(
			    std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_size_bytes(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_used_bytes(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_available_bytes(rand() %
			                                                                            100);
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_total_inodes(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_mounts())[i].set_used_inodes(rand() % 100);
		}
		for (int i = 0; i < 5; i++)
		{  // get some repeats
			(*input.mutable_containers())[0].add_network_by_serverports()->set_port(rand() % 2);
			generate_connection_categories(
			    (*(*input.mutable_containers())[0].mutable_network_by_serverports())[i]
			        .mutable_counters());
		}
		(*input.mutable_containers())[0].set_mesos_task_id("209fasd");
		(*input.mutable_containers())[0].set_image_id("sedrfa");
		for (int i = 0; i < 100; i++)
		{
			(*input.mutable_containers())[0].add_commands()->set_timestamp(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_count(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_cmdline(
			    std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_comm(
			    std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_pid(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_ppid(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_uid(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_cwd(
			    std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_login_shell_id(rand() %
			                                                                             2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_login_shell_distance(
			    rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_tty(rand() % 2);
			(*(*input.mutable_containers())[0].mutable_commands())[i].set_category(
			    (draiosproto::command_category)(rand() % 2));
		}
		for (int i = 0; i < 5; i++)
		{
			(*input.mutable_containers())[0].add_orchestrators_fallback_labels()->set_key(
			    std::to_string(10 * i + (rand() % 2)));
			(*(*input.mutable_containers())[0].mutable_orchestrators_fallback_labels())[i]
			    .set_value(std::to_string(rand() % 2));
		}
		(*input.mutable_containers())[0].set_image_repo(";ohji");
		(*input.mutable_containers())[0].set_image_tag("89ujp7");
		(*input.mutable_containers())[0].set_image_digest("kjnml;");
		(*input.mutable_containers())[0].add_container_reporting_group_id(2309);
		(*input.mutable_containers())[0].add_container_reporting_group_id(90);
		(*input.mutable_containers())[0].add_container_reporting_group_id(342);
		(*input.mutable_containers())[0].add_top_files()->set_name("w0asdiouf ");
		(*(*input.mutable_containers())[0].mutable_top_files())[0].set_bytes(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_top_files())[0].set_time_ns(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_top_files())[0].set_open_count(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_top_files())[0].set_errors(rand() % 100);
		for (int i = 1; i < 5; i++)
		{
			(*input.mutable_containers())[0].add_top_files()->set_name(std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_top_files())[i].set_bytes(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_top_files())[i].set_time_ns(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_top_files())[i].set_open_count(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_top_files())[i].set_errors(rand() % 100);
		}
		(*input.mutable_containers())[0].add_top_devices()->set_name("asd98uwef ");
		(*(*input.mutable_containers())[0].mutable_top_devices())[0].set_bytes(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_top_devices())[0].set_time_ns(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_top_devices())[0].set_open_count(rand() % 100);
		(*(*input.mutable_containers())[0].mutable_top_devices())[0].set_errors(rand() % 100);
		for (int i = 1; i < 5; i++)
		{
			(*input.mutable_containers())[0].add_top_devices()->set_name(
			    std::to_string(rand() % 2));
			(*(*input.mutable_containers())[0].mutable_top_devices())[i].set_bytes(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_top_devices())[i].set_time_ns(rand() % 100);
			(*(*input.mutable_containers())[0].mutable_top_devices())[i].set_open_count(rand() %
			                                                                            100);
			(*(*input.mutable_containers())[0].mutable_top_devices())[i].set_errors(rand() % 100);
		}

		for (int j = 1; j < 10; j++)
		{
			input.add_containers()->set_id(std::to_string(rand() % 5));
			(*input.mutable_containers())[j].set_type((draiosproto::container_type)3);
			(*input.mutable_containers())[j].set_name("089uasdf");
			(*input.mutable_containers())[j].set_image("209f");
			generate_time_categories((*input.mutable_containers())[j].mutable_tcounters());
			generate_transaction_breakdown_categories(
			    (*input.mutable_containers())[j].mutable_reqcounters());
			generate_counter_time_bidirectional(
			    (*input.mutable_containers())[j].mutable_transaction_counters());
			generate_counter_time_bidirectional(
			    (*input.mutable_containers())[j].mutable_max_transaction_counters());
			(*input.mutable_containers())[j].set_transaction_processing_delay(rand() % 100);
			(*input.mutable_containers())[j].set_next_tiers_delay(rand() % 100);
			generate_resource_categories(
			    (*input.mutable_containers())[j].mutable_resource_counters());
			generate_counter_syscall_errors(
			    (*input.mutable_containers())[j].mutable_syscall_errors());
			for (int i = 0; i < 10; i++)
			{
				(*input.mutable_containers())[j].add_port_mappings()->set_host_ip(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_port_mappings())[i].set_host_port(
				    rand() % 2);
				(*(*input.mutable_containers())[j].mutable_port_mappings())[i].set_container_ip(
				    rand() % 2);
				(*(*input.mutable_containers())[j].mutable_port_mappings())[i].set_container_port(
				    rand() % 2);
			}
			generate_proto_info((*input.mutable_containers())[j].mutable_protos());
			for (int i = 0; i < 5; i++)
			{
				(*input.mutable_containers())[j].add_labels()->set_key(
				    std::to_string(10 * j + (rand() % 2)));
				(*(*input.mutable_containers())[j].mutable_labels())[i].set_value(
				    std::to_string(rand() % 2));
			}
			(*input.mutable_containers())[j].add_mounts()->set_device("asdf09u");
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_mount_dir(
			    "e(*input.mutable_containers())[0].add_mounts");
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_type("0uwsdoifj");
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_size_bytes(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_used_bytes(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_available_bytes(rand() %
			                                                                            100);
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_total_inodes(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_mounts())[0].set_used_inodes(rand() % 100);

			for (int i = 1; i < 10; i++)
			{
				(*input.mutable_containers())[j].add_mounts()->set_device(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_mount_dir(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_type(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_size_bytes(rand() %
				                                                                       100);
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_used_bytes(rand() %
				                                                                       100);
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_available_bytes(rand() %
				                                                                            100);
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_total_inodes(rand() %
				                                                                         100);
				(*(*input.mutable_containers())[j].mutable_mounts())[i].set_used_inodes(rand() %
				                                                                        100);
			}
			for (int i = 0; i < 5; i++)
			{  // get some repeats
				(*input.mutable_containers())[j].add_network_by_serverports()->set_port(rand() % 2);
				generate_connection_categories(
				    (*(*input.mutable_containers())[j].mutable_network_by_serverports())[i]
				        .mutable_counters());
			}
			(*input.mutable_containers())[j].set_mesos_task_id("209fasd");
			(*input.mutable_containers())[j].set_image_id("sedrfa");
			for (int i = 0; i < 100; i++)
			{
				(*input.mutable_containers())[j].add_commands()->set_timestamp(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_count(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_cmdline(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_comm(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_pid(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_ppid(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_uid(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_cwd(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_login_shell_id(
				    rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_login_shell_distance(
				    rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_tty(rand() % 2);
				(*(*input.mutable_containers())[j].mutable_commands())[i].set_category(
				    (draiosproto::command_category)(rand() % 2));
			}
			for (int i = 0; i < 5; i++)
			{
				(*input.mutable_containers())[j].add_orchestrators_fallback_labels()->set_key(
				    std::to_string(10 * i + (rand() % 2)));
				(*(*input.mutable_containers())[j].mutable_orchestrators_fallback_labels())[i]
				    .set_value(std::to_string(rand() % 2));
			}
			(*input.mutable_containers())[j].set_image_repo(";ohji");
			(*input.mutable_containers())[j].set_image_tag("89ujp7");
			(*input.mutable_containers())[j].set_image_digest("kjnml;");
			(*input.mutable_containers())[j].add_container_reporting_group_id(2309);
			(*input.mutable_containers())[j].add_container_reporting_group_id(90);
			(*input.mutable_containers())[j].add_container_reporting_group_id(342);
			(*input.mutable_containers())[j].add_top_files()->set_name("w0asdiouf ");
			(*(*input.mutable_containers())[j].mutable_top_files())[0].set_bytes(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_top_files())[0].set_time_ns(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_top_files())[0].set_open_count(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_top_files())[0].set_errors(rand() % 100);
			for (int i = 1; i < 5; i++)
			{
				(*input.mutable_containers())[j].add_top_files()->set_name(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_top_files())[i].set_bytes(rand() % 100);
				(*(*input.mutable_containers())[j].mutable_top_files())[i].set_time_ns(rand() %
				                                                                       100);
				(*(*input.mutable_containers())[j].mutable_top_files())[i].set_open_count(rand() %
				                                                                          100);
				(*(*input.mutable_containers())[j].mutable_top_files())[i].set_errors(rand() % 100);
			}
			(*input.mutable_containers())[j].add_top_devices()->set_name("asd98uwef ");
			(*(*input.mutable_containers())[j].mutable_top_devices())[0].set_bytes(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_top_devices())[0].set_time_ns(rand() % 100);
			(*(*input.mutable_containers())[j].mutable_top_devices())[0].set_open_count(rand() %
			                                                                            100);
			(*(*input.mutable_containers())[j].mutable_top_devices())[0].set_errors(rand() % 100);
			for (int i = 1; i < 5; i++)
			{
				(*input.mutable_containers())[j].add_top_devices()->set_name(
				    std::to_string(rand() % 2));
				(*(*input.mutable_containers())[j].mutable_top_devices())[i].set_bytes(rand() %
				                                                                       100);
				(*(*input.mutable_containers())[j].mutable_top_devices())[i].set_time_ns(rand() %
				                                                                         100);
				(*(*input.mutable_containers())[j].mutable_top_devices())[i].set_open_count(rand() %
				                                                                            100);
				(*(*input.mutable_containers())[j].mutable_top_devices())[i].set_errors(rand() %
				                                                                        100);
			}
		}

		// generate some mesos
		for (int i = 0; i < 50; i++)
		{
			input.mutable_mesos()->add_frameworks();
			generate_mesos_common(
			    (*input.mutable_mesos()->mutable_frameworks())[i].mutable_common());
			for (int j = 0; j < 10; j++)
			{
				(*input.mutable_mesos()->mutable_frameworks())[i].add_tasks();
				generate_mesos_common(
				    (*(*input.mutable_mesos()->mutable_frameworks())[i].mutable_tasks())[j]
				        .mutable_common());
				(*(*input.mutable_mesos()->mutable_frameworks())[i].mutable_tasks())[j]
				    .set_slave_id(std::to_string(rand() % 2));
			}
		}
		for (int i = 0; i < 50; i++)
		{
			generate_marathon_group(input.mutable_mesos()->add_groups());
		}
		for (int i = 0; i < 50; i++)
		{
			generate_mesos_common(input.mutable_mesos()->add_slaves()->mutable_common());
		}

		// generate some events
		for (int i = 0; i < 100; i++)
		{
			input.add_events();
			(*input.mutable_events())[i].set_timestamp_sec(rand() % 2);
			(*input.mutable_events())[i].set_scope(std::to_string(rand() % 2));
			(*input.mutable_events())[i].set_title(std::to_string(rand() % 2));
			(*input.mutable_events())[i].set_description(std::to_string(rand() % 2));
			(*input.mutable_events())[i].set_severity(rand() % 2);
			for (int j = 0; j <= rand() % 2; j++)
			{
				(*input.mutable_events())[i].add_tags();
				(*(*input.mutable_events())[i].mutable_tags())[j].set_key(
				    std::to_string(10 * j + (rand() % 2)));
				(*(*input.mutable_events())[i].mutable_tags())[j].set_value(
				    std::to_string(rand() % 2));
			}
		}

		// generate some falco baseline
		for (int i = 0; i < 50; i++)
		{
			input.mutable_falcobl()->add_progs();
			(*input.mutable_falcobl()->mutable_progs())[i].set_comm(std::to_string(rand() % 2));
			(*input.mutable_falcobl()->mutable_progs())[i].set_exe(std::to_string(rand() % 2));
			(*input.mutable_falcobl()->mutable_progs())[i].add_args("jjff");
			(*input.mutable_falcobl()->mutable_progs())[i].add_args("jjff");
			(*input.mutable_falcobl()->mutable_progs())[i].add_args("jjasdfjkl;ff");
			(*input.mutable_falcobl()->mutable_progs())[i].set_user_id(rand() % 2);
			(*input.mutable_falcobl()->mutable_progs())[i].set_container_id(
			    std::to_string(rand() % 2));
			for (int j = 0; j < rand() % 3; j++)  // j cats
			{
				(*input.mutable_falcobl()->mutable_progs())[i].add_cats();
				(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j].set_name(
				    std::to_string(rand() % 2));
				for (int k = 0; k < rand() % 3; k++)  // k subcat container
				{
					(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
					    .add_startup_subcats();
					(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
					    .add_regular_subcats();
					for (int l = 0; l < rand() % 3; l++)  // l subcats
					{
						(*(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
						      .mutable_startup_subcats())[k]
						    .add_subcats();
						(*(*(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
						        .mutable_startup_subcats())[k]
						      .mutable_subcats())[l]
						    .set_name(std::to_string(rand() % 2));
						for (int m = 0; m < rand() % 3; m++)  // m d's
						{
							(*(*(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
							        .mutable_startup_subcats())[k]
							      .mutable_subcats())[l]
							    .add_d(std::to_string(rand() % 2));
						}
						(*(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
						      .mutable_regular_subcats())[k]
						    .add_subcats();
						(*(*(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
						        .mutable_regular_subcats())[k]
						      .mutable_subcats())[l]
						    .set_name(std::to_string(rand() % 2));
						for (int m = 0; m < rand() % 3; m++)  // m d's
						{
							(*(*(*(*input.mutable_falcobl()->mutable_progs())[i].mutable_cats())[j]
							        .mutable_regular_subcats())[k]
							      .mutable_subcats())[l]
							    .add_d(std::to_string(rand() % 2));
						}
					}
				}
			}

			input.mutable_falcobl()->add_containers();
			(*input.mutable_falcobl()->mutable_containers())[i].set_id(std::to_string(rand() % 2));
			(*input.mutable_falcobl()->mutable_containers())[i].set_name(
			    std::to_string(rand() % 2));
			(*input.mutable_falcobl()->mutable_containers())[i].set_image_name(
			    std::to_string(rand() % 2));
			(*input.mutable_falcobl()->mutable_containers())[i].set_image_id(
			    std::to_string(rand() % 2));
		}

		// generate some commands
		for (int i = 0; i < 100; i++)
		{
			input.add_commands()->set_timestamp(rand() % 2);
			(*input.mutable_commands())[i].set_count(rand() % 2);
			(*input.mutable_commands())[i].set_cmdline(std::to_string(rand() % 2));
			(*input.mutable_commands())[i].set_comm(std::to_string(rand() % 2));
			(*input.mutable_commands())[i].set_pid(rand() % 2);
			(*input.mutable_commands())[i].set_ppid(rand() % 2);
			(*input.mutable_commands())[i].set_uid(rand() % 2);
			(*input.mutable_commands())[i].set_cwd(std::to_string(rand() % 2));
			(*input.mutable_commands())[i].set_login_shell_id(rand() % 2);
			(*input.mutable_commands())[i].set_login_shell_distance(rand() % 2);
			(*input.mutable_commands())[i].set_tty(rand() % 2);
			(*input.mutable_commands())[i].set_category(
			    (draiosproto::command_category)(rand() % 2));
		}

		// generate some swarm
		for (int i = 0; i < 50; i++)
		{
			input.mutable_swarm()->add_services();
			generate_swarm_common((*input.mutable_swarm()->mutable_services())[i].mutable_common());
			(*input.mutable_swarm()->mutable_services())[i].add_virtual_ips(
			    std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_services())[i].add_virtual_ips(
			    std::to_string(rand() % 2));
			for (int j = 0; j < 10; j++)
			{
				(*input.mutable_swarm()->mutable_services())[i].add_ports();
				(*(*input.mutable_swarm()->mutable_services())[i].mutable_ports())[j].set_port(
				    rand() % 2);
				(*(*input.mutable_swarm()->mutable_services())[i].mutable_ports())[j]
				    .set_published_port(rand() % 2);
				(*(*input.mutable_swarm()->mutable_services())[i].mutable_ports())[j].set_protocol(
				    std::to_string(rand() % 2));
			}
			(*input.mutable_swarm()->mutable_services())[i].set_mode(
			    (draiosproto::swarm_service_mode)(1 + (rand() % 2)));
			(*input.mutable_swarm()->mutable_services())[i].set_spec_replicas(rand() % 2);
			(*input.mutable_swarm()->mutable_services())[i].set_tasks(rand() % 2);
		}

		for (int i = 0; i < 50; i++)
		{
			input.mutable_swarm()->add_nodes();
			generate_swarm_common((*input.mutable_swarm()->mutable_nodes())[i].mutable_common());
			(*input.mutable_swarm()->mutable_nodes())[i].set_role(std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_nodes())[i].set_ip_address(std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_nodes())[i].set_version(std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_nodes())[i].set_availability(
			    std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_nodes())[i].set_state(std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_nodes())[i].mutable_manager()->set_leader(rand() % 2);
			(*input.mutable_swarm()->mutable_nodes())[i].mutable_manager()->set_reachability(
			    std::to_string(rand() % 2));
		}
		for (int i = 0; i < 50; i++)
		{
			input.mutable_swarm()->add_tasks();
			generate_swarm_common((*input.mutable_swarm()->mutable_tasks())[i].mutable_common());
			(*input.mutable_swarm()->mutable_tasks())[i].set_service_id(std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_tasks())[i].set_node_id(std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_tasks())[i].set_container_id(
			    std::to_string(rand() % 2));
			(*input.mutable_swarm()->mutable_tasks())[i].set_state(std::to_string(rand() % 2));
		}
		input.mutable_swarm()->set_quorum(rand() % 2);
		input.mutable_swarm()->set_node_id("wserftghiur");

		input.add_config_percentiles(1);
		input.add_config_percentiles(20);
		input.add_config_percentiles(45);
		input.add_config_percentiles(74);
		// generate some internal metrics
		for (int i = 0; i < 20; i++)
		{
			input.mutable_internal_metrics()->add_statsd_metrics();
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_name(
			    std::to_string(rand() % 2));
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].add_tags()->set_key(
			    std::to_string(rand() % 2));
			(*(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].mutable_tags())[0]
			    .set_value(std::to_string(rand() % 2));
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].add_tags()->set_key(
			    std::to_string(10 + (rand() % 2)));
			(*(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].mutable_tags())[1]
			    .set_value(std::to_string(rand() % 2));
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_type(
			    (draiosproto::statsd_metric_type)(1 + (rand() % 4)));
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_value(rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_sum(rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_min(rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_max(rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_count(rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_median(rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_percentile_95(
			    rand() % 2);
			(*input.mutable_internal_metrics()->mutable_statsd_metrics())[i].set_percentile_99(
			    rand() % 2);
		}

		// generate some incomplete connections
		input.add_ipv4_incomplete_connections_v2()->mutable_tuple()->set_sip(2340);
		(*input.mutable_ipv4_incomplete_connections_v2())[0].mutable_tuple()->set_dip(487);
		(*input.mutable_ipv4_incomplete_connections_v2())[0].mutable_tuple()->set_sport(3);
		(*input.mutable_ipv4_incomplete_connections_v2())[0].mutable_tuple()->set_dport(94);
		(*input.mutable_ipv4_incomplete_connections_v2())[0].mutable_tuple()->set_l4proto(2098);
		(*input.mutable_ipv4_incomplete_connections_v2())[0].set_spid(984);
		(*input.mutable_ipv4_incomplete_connections_v2())[0].set_dpid(884);
		generate_connection_categories(
		    (*input.mutable_ipv4_incomplete_connections_v2())[0].mutable_counters());
		(*input.mutable_ipv4_incomplete_connections_v2())[0].set_state(
		    (draiosproto::connection_state)(rand() % 3));
		(*input.mutable_ipv4_incomplete_connections_v2())[0].set_error_code(
		    (draiosproto::error_code)(1 + (rand() % 100)));

		for (int i = 1; i < 130; i++)  // guaranteed to get some repeats
		{
			input.add_ipv4_incomplete_connections_v2()->mutable_tuple()->set_sip(rand() % 2);
			(*input.mutable_ipv4_incomplete_connections_v2())[i].mutable_tuple()->set_dip(rand() %
			                                                                              2);
			(*input.mutable_ipv4_incomplete_connections_v2())[i].mutable_tuple()->set_sport(rand() %
			                                                                                2);
			(*input.mutable_ipv4_incomplete_connections_v2())[i].mutable_tuple()->set_dport(rand() %
			                                                                                2);
			(*input.mutable_ipv4_incomplete_connections_v2())[i].mutable_tuple()->set_l4proto(
			    rand() % 2);
			(*input.mutable_ipv4_incomplete_connections_v2())[i].set_spid(rand() % 2);
			(*input.mutable_ipv4_incomplete_connections_v2())[i].set_dpid(rand() % 2);
			generate_connection_categories(
			    (*input.mutable_ipv4_incomplete_connections_v2())[i].mutable_counters());
			(*input.mutable_ipv4_incomplete_connections_v2())[i].set_state(
			    (draiosproto::connection_state)(rand() % 3));
			(*input.mutable_ipv4_incomplete_connections_v2())[i].set_error_code(
			    (draiosproto::error_code)(1 + (rand() % 100)));
		}

		// generate some users
		for (int i = 0; i < 10; i++)
		{
			input.add_userdb();
			(*input.mutable_userdb())[i].set_id(rand() % 2);
			(*input.mutable_userdb())[i].set_name(std::to_string(rand() % 2));
		}
		// generate some environments
		for (int i = 0; i < 10; i++)
		{
			input.add_environments();
			(*input.mutable_environments())[i].set_hash(std::to_string(rand() % 2));
			(*input.mutable_environments())[i].add_variables(std::to_string(rand() % 2));
		}
		// generate some unreported counters
		generate_time_categories(input.mutable_unreported_counters()->mutable_tcounters());
		generate_transaction_breakdown_categories(
		    input.mutable_unreported_counters()->mutable_reqcounters());
		generate_counter_time_bidirectional(
		    input.mutable_unreported_counters()->mutable_max_transaction_counters());
		generate_resource_categories(
		    input.mutable_unreported_counters()->mutable_resource_counters());
		generate_counter_syscall_errors(
		    input.mutable_unreported_counters()->mutable_syscall_errors());
		generate_proto_info(input.mutable_unreported_counters()->mutable_protos());
		for (int i = 0; i < 5; i++)
		{
			input.mutable_unreported_counters()->add_names(std::to_string(rand() % 2));
		}
		generate_counter_time_bidirectional(
		    input.mutable_unreported_counters()->mutable_transaction_counters());

		// generate some reporting groups
		// nobody does anything with this. so just create a couple
		input.add_reporting_groups();
		(*input.mutable_reporting_groups())[0].set_id(rand() % 2);
		input.add_reporting_groups();
		(*input.mutable_reporting_groups())[1].set_id(rand() % 2);

		// generate some devices
		input.add_top_devices()->set_name("asd98uwef ");
		(*input.mutable_top_devices())[0].set_bytes(rand() % 100);
		(*input.mutable_top_devices())[0].set_time_ns(rand() % 100);
		(*input.mutable_top_devices())[0].set_open_count(rand() % 100);
		(*input.mutable_top_devices())[0].set_errors(rand() % 100);
		for (int i = 1; i < 5; i++)
		{
			input.add_top_devices()->set_name(std::to_string(rand() % 2));
			(*input.mutable_top_devices())[i].set_bytes(rand() % 100);
			(*input.mutable_top_devices())[i].set_time_ns(rand() % 100);
			(*input.mutable_top_devices())[i].set_open_count(rand() % 100);
			(*input.mutable_top_devices())[i].set_errors(rand() % 100);
		}

		std::ostringstream filename;
		filename << "random_" << loop_count << ".dam";
		std::ofstream output_file;
		output_file.open(filename.str().c_str(), std::ofstream::out | std::ofstream::binary);
		ASSERT_FALSE(output_file.fail());
		char temp2 = 2;
		char temp1 = 1;
		output_file.write(&temp2, 1);
		output_file.write(&temp1, 1);

		bool success = input.SerializeToOstream(&output_file);
		ASSERT_TRUE(success);
		output_file.close();
	}
}

TEST(aggregator_extra, DISABLED_generate_programs)
{
	draiosproto::metrics input;
	input.set_machine_id("asdlkfj");
	input.set_customer_id("20udasfi");
	input.set_timestamp_ns((uint64_t)1000000000);

	input.add_programs();
	(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->set_comm("");
	(*input.mutable_programs())[0].mutable_procinfo()->mutable_details()->set_exe("");

	input.add_programs()->mutable_procinfo()->mutable_details()->set_comm("sfdjkl");
	(*input.mutable_programs())[1].mutable_procinfo()->mutable_details()->set_exe("");

	input.add_programs()->mutable_procinfo()->mutable_details()->set_exe("3fuj84");
	(*input.mutable_programs())[2].mutable_procinfo()->mutable_details()->set_comm("");

	input.add_programs()->mutable_procinfo()->mutable_details()->add_args("9034fj8iu");
	(*input.mutable_programs())[3].mutable_procinfo()->mutable_details()->set_comm("");
	(*input.mutable_programs())[3].mutable_procinfo()->mutable_details()->set_exe("");

	input.add_programs();
	(*input.mutable_programs())[4].mutable_procinfo()->mutable_details()->set_comm("");
	(*input.mutable_programs())[4].mutable_procinfo()->mutable_details()->set_exe("");
	(*input.mutable_programs())[4].mutable_procinfo()->mutable_details()->add_args("wafuj8");
	(*input.mutable_programs())[4].mutable_procinfo()->mutable_details()->add_args("afjiods");

	input.add_programs()->mutable_procinfo()->mutable_details()->set_exe("3fu: j84");
	(*input.mutable_programs())[5].mutable_procinfo()->mutable_details()->set_comm("");

	input.add_programs()->mutable_procinfo()->mutable_details()->set_container_id("a;sdjklf");
	(*input.mutable_programs())[6].mutable_procinfo()->mutable_details()->set_comm("");
	(*input.mutable_programs())[6].mutable_procinfo()->mutable_details()->set_exe("");

	input.add_programs()->set_environment_hash("asd;lkjf");
	(*input.mutable_programs())[7].mutable_procinfo()->mutable_details()->set_comm("");
	(*input.mutable_programs())[7].mutable_procinfo()->mutable_details()->set_exe("");

	input.add_programs();
	(*input.mutable_programs())[8].mutable_procinfo()->mutable_details()->set_comm("comm");
	(*input.mutable_programs())[8].mutable_procinfo()->mutable_details()->set_exe("exe");
	(*input.mutable_programs())[8].mutable_procinfo()->mutable_details()->add_args("arg1");
	(*input.mutable_programs())[8].mutable_procinfo()->mutable_details()->add_args("arg2");
	(*input.mutable_programs())[8].mutable_procinfo()->mutable_details()->add_args("arg1");
	(*input.mutable_programs())[8].mutable_procinfo()->mutable_details()->set_container_id(
	    "container_id");
	(*input.mutable_programs())[8].set_environment_hash("environment_hash");

	std::ostringstream filename;
	filename << "programs.dam";
	std::ofstream output_file;
	output_file.open(filename.str().c_str(), std::ofstream::out | std::ofstream::binary);
	ASSERT_FALSE(output_file.fail());
	char temp2 = 2;
	char temp1 = 1;
	output_file.write(&temp2, 1);
	output_file.write(&temp1, 1);

	bool success = input.SerializeToOstream(&output_file);
	ASSERT_TRUE(success);
	output_file.close();
}
