#include <gtest.h>

#include <fstream>
#include <iostream>

#include "aggregator_limits.h"
#include "aggregator_overrides.h"
#include "draios.pb.h"
#include "draios.proto.h"
#include "draios.helpers.h"
#include "scoped_config.h"

TEST(aggregator_overrides, process_details_args)
{
	message_aggregator_builder_impl builder;
	process_details_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::process_details;
	auto output = new draiosproto::process_details;

	input->add_args("1");
	input->add_args("1");

	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->args().size(), 2);
	EXPECT_EQ(output->args()[0], "1");
	EXPECT_EQ(output->args()[1], "1");
	delete input;
	ASSERT_EQ(output->args().size(), 2);
	EXPECT_EQ(output->args()[0], "1");
	EXPECT_EQ(output->args()[1], "1");

	input = new draiosproto::process_details;
	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->args().size(), 2);
	EXPECT_EQ(output->args()[0], "1");
	EXPECT_EQ(output->args()[1], "1");

	input->add_args("2");
	aggregator.aggregate(*input, *output, false);
	delete input;
	ASSERT_EQ(output->args().size(), 2);
	EXPECT_EQ(output->args()[0], "1");
	EXPECT_EQ(output->args()[1], "1");

	delete output;
}

TEST(aggregator_overrides, process_details_args_in_place)
{
	message_aggregator_builder_impl builder;
	process_details_message_aggregator_impl aggregator(builder);

	auto output = new draiosproto::process_details;

	output->add_args("1");
	output->add_args("1");

	aggregator.aggregate(*output, *output, true);
	ASSERT_EQ(output->args().size(), 2);
	EXPECT_EQ(output->args()[0], "1");
	EXPECT_EQ(output->args()[1], "1");

	auto input = new draiosproto::process_details;
	input->add_args("2");
	aggregator.aggregate(*input, *output, false);
	delete input;
	ASSERT_EQ(output->args().size(), 2);
	EXPECT_EQ(output->args()[0], "1");
	EXPECT_EQ(output->args()[1], "1");

	delete output;
}

TEST(aggregator_overrides, process_details_container_id)
{
	message_aggregator_builder_impl builder;
	process_details_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::process_details;
	auto output = new draiosproto::process_details;

	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->container_id(), "");

	input->set_container_id("1");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->container_id(), "1");
	delete input;
	EXPECT_EQ(output->container_id(), "1");
	delete output;
}

TEST(aggregator_overrides, process_details_container_id_in_place)
{
	message_aggregator_builder_impl builder;
	process_details_message_aggregator_impl aggregator(builder);

	auto output = new draiosproto::process_details;

	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->container_id(), "");
	output->set_container_id("1");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->container_id(), "1");
	delete output;
}

TEST(aggregator_overrides, process_netrole)
{
	message_aggregator_builder_impl builder;
	process_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::process;
	auto output = new draiosproto::process;

	input->set_netrole(draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT);
	EXPECT_EQ(output->is_ipv4_transaction_client(), true);
	EXPECT_EQ(output->is_ipv4_transaction_server(), false);

	input->set_netrole(draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT | draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	EXPECT_EQ(output->is_ipv4_transaction_client(), true);
	EXPECT_EQ(output->is_ipv4_transaction_server(), true);

	aggregator.reset();

	input->set_netrole(0);
	input->set_is_ipv4_transaction_server(true);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	EXPECT_EQ(output->is_ipv4_transaction_client(), false);
	EXPECT_EQ(output->is_ipv4_transaction_server(), true);

	input->set_is_ipv4_transaction_client(true);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT | draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	EXPECT_EQ(output->is_ipv4_transaction_client(), true);
	EXPECT_EQ(output->is_ipv4_transaction_server(), true);

	delete input;
	delete output;
}

TEST(aggregator_overrides, process_netrole_in_place)
{
	message_aggregator_builder_impl builder;
	process_message_aggregator_impl aggregator(builder);

	auto output = new draiosproto::process;

	output->set_netrole(draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT);
	EXPECT_EQ(output->is_ipv4_transaction_client(), true);
	EXPECT_EQ(output->is_ipv4_transaction_server(), false);

	output->set_netrole(draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT | draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	EXPECT_EQ(output->is_ipv4_transaction_client(), true);
	EXPECT_EQ(output->is_ipv4_transaction_server(), true);

	aggregator.reset();
	output->clear_netrole();
	output->clear_is_ipv4_transaction_server();
	output->clear_is_ipv4_transaction_client();

	output->set_netrole(0);
	output->set_is_ipv4_transaction_server(true);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	EXPECT_EQ(output->is_ipv4_transaction_client(), false);
	EXPECT_EQ(output->is_ipv4_transaction_server(), true);

	aggregator.reset();
	output->clear_netrole();
	output->set_is_ipv4_transaction_client(true);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->netrole(), draiosproto::networkrole::IS_REMOTE_IPV4_CLIENT | draiosproto::networkrole::IS_REMOTE_IPV4_SERVER);
	EXPECT_EQ(output->is_ipv4_transaction_client(), true);
	EXPECT_EQ(output->is_ipv4_transaction_server(), true);
	delete output;
}

TEST(aggregator_overrides, metrics_sampling_ratio)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	input->set_sampling_ratio(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->sampling_ratio(), 2);
	EXPECT_EQ(output->aggr_sampling_ratio().sum(), 2);
	input->set_sampling_ratio(3);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->sampling_ratio(), 2);
	EXPECT_EQ(output->aggr_sampling_ratio().sum(), 5);
	delete input;
	EXPECT_EQ(output->sampling_ratio(), 2);
	EXPECT_EQ(output->aggr_sampling_ratio().sum(), 5);
	delete output;

	output = new draiosproto::metrics;
	output->set_sampling_ratio(4);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->sampling_ratio(), 4);
	EXPECT_EQ(output->aggr_sampling_ratio().sum(), 4);
	delete output;
}

TEST(aggregator_overrides, metrics_programs)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	auto in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("asdlkfj");
	in->add_pids(1);
	in->add_pids(2);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("u890s");
	in->add_pids(3);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	size_t hash0 = input->programs()[0].tiuid();
	size_t hash1 = input->programs()[1].tiuid();

	aggregator.aggregate(*input, *output, false);
	delete input;
	ASSERT_EQ(output->programs().size(), 2);
	EXPECT_EQ(output->programs()[0].pids()[0], hash0);
	EXPECT_EQ(output->programs()[1].pids()[0], hash1);

	input = new draiosproto::metrics;
	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("asdlkfj");
	in->add_pids(1);
	in->add_pids(2);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("u890s");
	in->add_pids(3);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("different!");
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	size_t hash2 = input->programs()[2].tiuid();

	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->programs().size(), 3);
	EXPECT_EQ(output->programs()[0].pids()[0], hash0);
	EXPECT_EQ(output->programs()[1].pids()[0], hash1);
	EXPECT_EQ(output->programs()[2].pids()[0], hash2);
	delete input;
	ASSERT_EQ(output->programs().size(), 3);
	EXPECT_EQ(output->programs()[0].pids()[0], hash0);
	EXPECT_EQ(output->programs()[1].pids()[0], hash1);
	EXPECT_EQ(output->programs()[2].pids()[0], hash2);

	delete output;
}

TEST(aggregator_overrides, metrics_programs_in_place)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto output = new draiosproto::metrics;

	auto in = output->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("asdlkfj");
	in->add_pids(1);
	in->add_pids(2);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = output->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("u890s");
	in->add_pids(3);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = output->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("u890s");
	in->add_pids(3);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	size_t hash0 = output->programs()[0].tiuid();
	size_t hash1 = output->programs()[1].tiuid();
	aggregator.aggregate(*output, *output, true);
	ASSERT_EQ(output->programs().size(), 2);
	EXPECT_EQ(output->programs()[0].pids()[0], hash0);
	EXPECT_EQ(output->programs()[1].pids()[0], hash1);

	auto input = new draiosproto::metrics;
	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("asdlkfj");
	in->add_pids(1);
	in->add_pids(2);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("u890s");
	in->add_pids(3);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	in = input->add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("different!");
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	size_t hash2 = input->programs()[2].tiuid();

	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->programs().size(), 3);
	EXPECT_EQ(output->programs()[0].pids()[0], hash0);
	EXPECT_EQ(output->programs()[1].pids()[0], hash1);
	EXPECT_EQ(output->programs()[2].pids()[0], hash2);
	delete input;
	ASSERT_EQ(output->programs().size(), 3);
	EXPECT_EQ(output->programs()[0].pids()[0], hash0);
	EXPECT_EQ(output->programs()[1].pids()[0], hash1);
	EXPECT_EQ(output->programs()[2].pids()[0], hash2);

	delete output;
}

TEST(aggregator_overrides, metrics_config_percentiles)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	output->add_config_percentiles(2);
	output->add_config_percentiles(3);
	aggregator.aggregate(*output, *output, true);
	ASSERT_EQ(output->config_percentiles().size(), 2);
	EXPECT_EQ(output->config_percentiles()[0], 2);
	EXPECT_EQ(output->config_percentiles()[1], 3);

	input->add_config_percentiles(1);
	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->config_percentiles().size(), 1);
	EXPECT_EQ(output->config_percentiles()[0], 1);

	delete input;
	ASSERT_EQ(output->config_percentiles().size(), 1);
	EXPECT_EQ(output->config_percentiles()[0], 1);

	delete output;
}

TEST(aggregator_overrides, metrics_falcobl)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	output->mutable_falcobl()->add_progs()->set_comm("1");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->falcobl().progs().size(), 1);

	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->falcobl().progs().size(), 1);

	input->mutable_falcobl()->add_progs()->set_comm("2");
	input->mutable_falcobl()->add_progs()->set_comm("3");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->falcobl().progs().size(), 2);
	EXPECT_EQ(output->falcobl().progs()[0].comm(), "2");
	EXPECT_EQ(output->falcobl().progs()[1].comm(), "3");
	delete input;
	EXPECT_EQ(output->falcobl().progs().size(), 2);
	EXPECT_EQ(output->falcobl().progs()[0].comm(), "2");
	EXPECT_EQ(output->falcobl().progs()[1].comm(), "3");
	delete output;
}

TEST(aggregator_overrides, metrics_commands)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	output->add_commands()->set_timestamp(1);
	output->add_commands()->set_timestamp(2);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->commands().size(), 2);

	input->add_commands()->set_timestamp(4);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->commands().size(), 3);
	EXPECT_EQ(output->commands()[0].timestamp(), 1);
	EXPECT_EQ(output->commands()[1].timestamp(), 2);
	EXPECT_EQ(output->commands()[2].timestamp(), 4);
	delete input;
	EXPECT_EQ(output->commands().size(), 3);
	EXPECT_EQ(output->commands()[0].timestamp(), 1);
	EXPECT_EQ(output->commands()[1].timestamp(), 2);
	EXPECT_EQ(output->commands()[2].timestamp(), 4);
	delete output;
}

TEST(aggregator_overrides, metrics_swarm)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	output->mutable_swarm()->set_node_id("1");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->swarm().node_id(), "");

	output->mutable_swarm()->set_node_id("1");
	output->mutable_swarm()->add_nodes()->mutable_common()->set_id("1");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->swarm().node_id(), "1");
	EXPECT_EQ(output->swarm().nodes().size(), 1);

	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->swarm().node_id(), "1");
	EXPECT_EQ(output->swarm().nodes().size(), 1);

	input->mutable_swarm()->add_nodes()->mutable_common()->set_id("2");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->swarm().node_id(), "1");
	EXPECT_EQ(output->swarm().nodes().size(), 2);
	delete input;
	EXPECT_EQ(output->swarm().node_id(), "1");
	EXPECT_EQ(output->swarm().nodes().size(), 2);
	delete output;
}

TEST(aggregator_overrides, metrics_ipv4_connections)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	auto in = output->add_ipv4_connections();
	in->mutable_tuple()->set_sip(1);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	in->mutable_counters()->set_n_aggregated_connections(1);

	in = output->add_ipv4_connections();
	in->mutable_tuple()->set_sip(2);
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	in->mutable_counters()->set_n_aggregated_connections(2);

	in = output->add_ipv4_connections();
	in->mutable_tuple()->set_sip(1);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	in->mutable_counters()->set_n_aggregated_connections(3);

	in = output->add_ipv4_connections();
	in->mutable_tuple()->set_sip(2);
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	in->mutable_counters()->set_n_aggregated_connections(4);

	*input = *output;
	aggregator.aggregate(*output, *output, true);
	ASSERT_EQ(output->ipv4_connections().size(), 2);
	EXPECT_EQ(output->ipv4_connections()[0].tuple().sip(), 1);
	EXPECT_EQ(output->ipv4_connections()[0].state(), draiosproto::connection_state::CONN_SUCCESS);
	EXPECT_EQ(output->ipv4_connections()[0].counters().aggr_n_aggregated_connections().sum(), 4);
	EXPECT_EQ(output->ipv4_connections()[1].tuple().sip(), 2);
	EXPECT_EQ(output->ipv4_connections()[1].counters().aggr_n_aggregated_connections().sum(), 0);

	in = input->add_ipv4_connections();
	in->mutable_tuple()->set_sip(3);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	in->mutable_counters()->set_n_aggregated_connections(6);
	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->ipv4_connections().size(), 3);
	EXPECT_EQ(output->ipv4_connections()[0].tuple().sip(), 1);
	EXPECT_EQ(output->ipv4_connections()[0].state(), draiosproto::connection_state::CONN_SUCCESS);
	EXPECT_EQ(output->ipv4_connections()[0].counters().aggr_n_aggregated_connections().sum(), 8);
	EXPECT_EQ(output->ipv4_connections()[1].tuple().sip(), 2);
	EXPECT_EQ(output->ipv4_connections()[1].counters().aggr_n_aggregated_connections().sum(), 0);
	EXPECT_EQ(output->ipv4_connections()[2].tuple().sip(), 3);
	EXPECT_EQ(output->ipv4_connections()[2].counters().aggr_n_aggregated_connections().sum(), 6);

	delete input;
	ASSERT_EQ(output->ipv4_connections().size(), 3);
	EXPECT_EQ(output->ipv4_connections()[0].tuple().sip(), 1);
	EXPECT_EQ(output->ipv4_connections()[0].state(), draiosproto::connection_state::CONN_SUCCESS);
	EXPECT_EQ(output->ipv4_connections()[0].counters().aggr_n_aggregated_connections().sum(), 8);
	EXPECT_EQ(output->ipv4_connections()[1].tuple().sip(), 2);
	EXPECT_EQ(output->ipv4_connections()[1].counters().aggr_n_aggregated_connections().sum(), 0);
	EXPECT_EQ(output->ipv4_connections()[2].tuple().sip(), 3);
	EXPECT_EQ(output->ipv4_connections()[2].counters().aggr_n_aggregated_connections().sum(), 6);

	delete output;
}

TEST(aggregator_overrides, metrics_ipv4_incomplete_connections_v2)
{
	message_aggregator_builder_impl builder;
	metrics_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::metrics;
	auto output = new draiosproto::metrics;

	auto in = output->add_ipv4_incomplete_connections_v2();
	in->mutable_tuple()->set_sip(1);
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	in->mutable_counters()->set_n_aggregated_connections(1);

	in = output->add_ipv4_incomplete_connections_v2();
	in->mutable_tuple()->set_sip(2);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	in->mutable_counters()->set_n_aggregated_connections(2);

	in = output->add_ipv4_incomplete_connections_v2();
	in->mutable_tuple()->set_sip(1);
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	in->mutable_counters()->set_n_aggregated_connections(3);

	in = output->add_ipv4_incomplete_connections_v2();
	in->mutable_tuple()->set_sip(2);
	in->set_state(draiosproto::connection_state::CONN_SUCCESS);
	in->mutable_counters()->set_n_aggregated_connections(4);

	*input = *output;
	aggregator.aggregate(*output, *output, true);
	ASSERT_EQ(output->ipv4_incomplete_connections_v2().size(), 2);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].tuple().sip(), 1);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].state(), draiosproto::connection_state::CONN_FAILED);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].counters().aggr_n_aggregated_connections().sum(), 4);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[1].tuple().sip(), 2);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[1].counters().aggr_n_aggregated_connections().sum(), 0);

	in = input->add_ipv4_incomplete_connections_v2();
	in->mutable_tuple()->set_sip(3);
	in->set_state(draiosproto::connection_state::CONN_FAILED);
	in->mutable_counters()->set_n_aggregated_connections(6);
	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->ipv4_incomplete_connections_v2().size(), 3);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].tuple().sip(), 1);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].state(), draiosproto::connection_state::CONN_FAILED);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].counters().aggr_n_aggregated_connections().sum(), 8);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[1].tuple().sip(), 2);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[1].counters().aggr_n_aggregated_connections().sum(), 0);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[2].tuple().sip(), 3);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[2].counters().aggr_n_aggregated_connections().sum(), 6);

	delete input;
	ASSERT_EQ(output->ipv4_incomplete_connections_v2().size(), 3);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].tuple().sip(), 1);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].state(), draiosproto::connection_state::CONN_FAILED);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[0].counters().aggr_n_aggregated_connections().sum(), 8);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[1].tuple().sip(), 2);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[1].counters().aggr_n_aggregated_connections().sum(), 0);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[2].tuple().sip(), 3);
	EXPECT_EQ(output->ipv4_incomplete_connections_v2()[2].counters().aggr_n_aggregated_connections().sum(), 6);

	delete output;
}


// ensure that upon aggregating programs and connections, pids are properly substituted
// for the pid-invariant identifier
TEST(aggregator_overrides, pid_substitution)
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

	in = input.add_programs();
	in->mutable_procinfo()->mutable_details()->set_exe("u890s");
	in->add_pids(3);
	in->set_tiuid(draiosproto::program_java_hasher(*in));

	input.add_ipv4_connections()->set_spid(1);
	(*input.mutable_ipv4_connections())[0].set_dpid(2);
	(*input.mutable_ipv4_connections())[0].set_state(draiosproto::connection_state::CONN_SUCCESS);
	input.add_ipv4_incomplete_connections_v2()->set_spid(3);
	(*input.mutable_ipv4_incomplete_connections_v2())[0].set_dpid(4);
	(*input.mutable_ipv4_incomplete_connections_v2())[0].set_state(draiosproto::connection_state::CONN_PENDING);
	auto input2 = input;
	aggregator.aggregate(input2, output, false);
	aggregator.override_primary_keys(output);

	EXPECT_EQ(output.programs()[0].pids()[0], input.programs()[0].tiuid());
	EXPECT_EQ(output.programs()[1].pids()[0], input.programs()[1].tiuid());
	EXPECT_EQ(output.ipv4_connections()[0].spid(), output.programs()[0].pids()[0]);
	EXPECT_EQ(output.ipv4_connections()[0].dpid(), output.programs()[0].pids()[0]);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[0].spid(), output.programs()[1].pids()[0]);
	EXPECT_EQ(output.ipv4_incomplete_connections_v2()[0].dpid(), 4);
}


TEST(aggregator_overrides, prom_canonical_name)
{
	draiosproto::prom_metric metric;

	metric.set_name("name");
	EXPECT_EQ(prometheus_info_message_aggregator_impl::get_canonical_name(metric), "name");
	metric.set_type(draiosproto::app_metric_type::APP_METRIC_TYPE_PROMETHEUS_RAW);
	EXPECT_EQ(prometheus_info_message_aggregator_impl::get_canonical_name(metric), "raw:name");
	auto tag = metric.add_tags();
	tag->set_key("key");
	tag->set_value("value");
	EXPECT_EQ(prometheus_info_message_aggregator_impl::get_canonical_name(metric), "raw:namekeyvalue");
	tag = metric.add_tags();
	tag->set_key("key2");
	tag->set_value("value2");
	EXPECT_EQ(prometheus_info_message_aggregator_impl::get_canonical_name(metric), "raw:namekeyvaluekey2value2");
}

TEST(aggregator_overrides, prom_metrics)
{
	test_helpers::scoped_config<bool> enable_prom_agg("aggregate_prometheus", true);
	message_aggregator_builder_impl builder;
	prometheus_info_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::prometheus_info;
	auto output = new draiosproto::prometheus_info;

	auto in = output->add_metrics();
	in->set_name("name");
	in->set_value(2);
	aggregator.aggregate(*output, *output, true);
	ASSERT_EQ(output->metrics().size(), 1);
	EXPECT_EQ(output->metrics()[0].value(), 0);
	EXPECT_EQ(output->metrics()[0].aggr_value_double().sum(), 2);

	in = input->add_metrics();
	in->set_name("name");
	in->set_value(3);
	in = input->add_metrics();
	in->set_name("name2");
	in->set_value(6);

	aggregator.aggregate(*input, *output, false);
	ASSERT_EQ(output->metrics().size(), 2);
	EXPECT_EQ(output->metrics()[0].aggr_value_double().sum(), 5);
	EXPECT_EQ(output->metrics()[1].aggr_value_double().sum(), 6);

	delete input;
	ASSERT_EQ(output->metrics().size(), 2);
	EXPECT_EQ(output->metrics()[0].aggr_value_double().sum(), 5);
	EXPECT_EQ(output->metrics()[1].aggr_value_double().sum(), 6);
	delete output;
}

TEST(aggregator_overrides, container_commands)
{
	message_aggregator_builder_impl builder;
	container_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::container;
	auto output = new draiosproto::container;

	output->add_commands()->set_timestamp(1);
	output->add_commands()->set_timestamp(2);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->commands().size(), 2);

	input->add_commands()->set_timestamp(4);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->commands().size(), 3);
	EXPECT_EQ(output->commands()[0].timestamp(), 1);
	EXPECT_EQ(output->commands()[1].timestamp(), 2);
	EXPECT_EQ(output->commands()[2].timestamp(), 4);
	delete input;
	EXPECT_EQ(output->commands().size(), 3);
	EXPECT_EQ(output->commands()[0].timestamp(), 1);
	EXPECT_EQ(output->commands()[1].timestamp(), 2);
	EXPECT_EQ(output->commands()[2].timestamp(), 4);
	delete output;
}

TEST(aggregator_overrides, event_tags)
{
	message_aggregator_builder_impl builder;
	agent_event_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::agent_event;
	auto output = new draiosproto::agent_event;

	output->add_tags()->set_key("1");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->tags()[0].key(), "1");

	input->add_tags()->set_key("2");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->tags()[0].key(), "2");

	delete input;
	EXPECT_EQ(output->tags()[0].key(), "2");
	delete output;
}

TEST(aggregator_overrides, resource_categories_capacity_score)
{
	message_aggregator_builder_impl builder;
	resource_categories_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::resource_categories;
	auto output = new draiosproto::resource_categories;

	uint32_t invalid_capacity_score = 4294967196;
	output->set_capacity_score(invalid_capacity_score);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->capacity_score(), 0);
	EXPECT_EQ(output->aggr_capacity_score().sum(), 0);

	output->set_capacity_score(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->capacity_score(), 0);
	EXPECT_EQ(output->aggr_capacity_score().sum(), 1);

	input->set_capacity_score(invalid_capacity_score);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->capacity_score(), 0);
	EXPECT_EQ(output->aggr_capacity_score().sum(), 1);

	input->set_capacity_score(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->capacity_score(), 0);
	EXPECT_EQ(output->aggr_capacity_score().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, resource_categories_stolen_capacity_score)
{
	message_aggregator_builder_impl builder;
	resource_categories_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::resource_categories;
	auto output = new draiosproto::resource_categories;

	uint32_t invalid_stolen_capacity_score = 4294967196;
	output->set_stolen_capacity_score(invalid_stolen_capacity_score);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->stolen_capacity_score(), 0);
	EXPECT_EQ(output->aggr_stolen_capacity_score().sum(), 0);

	output->set_stolen_capacity_score(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->stolen_capacity_score(), 0);
	EXPECT_EQ(output->aggr_stolen_capacity_score().sum(), 1);

	input->set_stolen_capacity_score(invalid_stolen_capacity_score);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->stolen_capacity_score(), 0);
	EXPECT_EQ(output->aggr_stolen_capacity_score().sum(), 1);

	input->set_stolen_capacity_score(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->stolen_capacity_score(), 0);
	EXPECT_EQ(output->aggr_stolen_capacity_score().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, k8s_node_host_ips)
{
	message_aggregator_builder_impl builder;
	k8s_node_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::k8s_node;
	auto output = new draiosproto::k8s_node;

	output->add_host_ips("1");
	output->add_host_ips("2");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->host_ips().size(), 2);

	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->host_ips().size(), 2);

	input->add_host_ips("3");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->host_ips().size(), 1);
	EXPECT_EQ(output->host_ips()[0], "3");
	delete input;
	EXPECT_EQ(output->host_ips().size(), 1);
	EXPECT_EQ(output->host_ips()[0], "3");
	delete output;
}

TEST(aggregator_overrides, k8s_service_ports)
{
	message_aggregator_builder_impl builder;
	k8s_service_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::k8s_service;
	auto output = new draiosproto::k8s_service;

	output->add_ports()->set_port(1);
	output->add_ports()->set_port(2);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->ports().size(), 2);

	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->ports().size(), 2);

	input->add_ports()->set_port(3);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->ports().size(), 1);
	EXPECT_EQ(output->ports()[0].port(), 3);
	delete input;
	EXPECT_EQ(output->ports().size(), 1);
	EXPECT_EQ(output->ports()[0].port(), 3);
	delete output;
}

TEST(aggregator_overrides, swarm_task_state)
{
	message_aggregator_builder_impl builder;
	swarm_task_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::swarm_task;
	auto output = new draiosproto::swarm_task;

	output->set_state("foo");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->state(), "foo");

	input->set_state("foo");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->state(), "foo");

	input->set_state("bar");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->state(), "bar, foo");
	delete input;
	EXPECT_EQ(output->state(), "bar, foo");
	delete output;
}

TEST(aggregator_overrides, swarm_node_state)
{
	message_aggregator_builder_impl builder;
	swarm_node_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::swarm_node;
	auto output = new draiosproto::swarm_node;

	output->set_state("foo");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->state(), "foo");

	input->set_state("foo");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->state(), "foo");

	input->set_state("bar");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->state(), "bar, foo");
	delete input;
	EXPECT_EQ(output->state(), "bar, foo");
	delete output;
}

TEST(aggregator_overrides, swarm_node_availability)
{
	message_aggregator_builder_impl builder;
	swarm_node_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::swarm_node;
	auto output = new draiosproto::swarm_node;

	output->set_availability("foo");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->availability(), "foo");

	input->set_availability("foo");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->availability(), "foo");

	input->set_availability("bar");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->availability(), "bar, foo");
	delete input;
	EXPECT_EQ(output->availability(), "bar, foo");
	delete output;
}

TEST(aggregator_overrides, swarm_node_version)
{
	message_aggregator_builder_impl builder;
	swarm_node_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::swarm_node;
	auto output = new draiosproto::swarm_node;

	output->set_version("foo");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->version(), "foo");

	input->set_version("foo");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->version(), "foo");

	input->set_version("bar");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->version(), "bar, foo");
	delete input;
	EXPECT_EQ(output->version(), "bar, foo");
	delete output;
}

TEST(aggregator_overrides, swarm_manager_reachability)
{
	message_aggregator_builder_impl builder;
	swarm_manager_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::swarm_manager;
	auto output = new draiosproto::swarm_manager;

	output->set_reachability("foo");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->reachability(), "foo");

	input->set_reachability("foo");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->reachability(), "foo");

	input->set_reachability("bar");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->reachability(), "bar, foo");
	delete input;
	EXPECT_EQ(output->reachability(), "bar, foo");
	delete output;
}

TEST(aggregator_overrides, statsd_metric_sum)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_sum(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->sum(), 0);
	EXPECT_EQ(output->aggr_sum().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_sum(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->sum(), 0);
	EXPECT_EQ(output->aggr_sum().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_sum(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->sum(), 0);
	EXPECT_EQ(output->aggr_sum().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->sum(), 0);
	EXPECT_EQ(output->aggr_sum().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_min)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_min(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->min(), 0);
	EXPECT_EQ(output->aggr_min().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_min(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->min(), 0);
	EXPECT_EQ(output->aggr_min().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_min(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->min(), 0);
	EXPECT_EQ(output->aggr_min().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->min(), 0);
	EXPECT_EQ(output->aggr_min().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_max)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_max(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->max(), 0);
	EXPECT_EQ(output->aggr_max().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_max(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->max(), 0);
	EXPECT_EQ(output->aggr_max().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_max(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->max(), 0);
	EXPECT_EQ(output->aggr_max().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->max(), 0);
	EXPECT_EQ(output->aggr_max().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_count)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_count(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->count(), 0);
	EXPECT_EQ(output->aggr_count().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_count(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->count(), 0);
	EXPECT_EQ(output->aggr_count().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_count(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->count(), 0);
	EXPECT_EQ(output->aggr_count().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->count(), 0);
	EXPECT_EQ(output->aggr_count().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_median)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_median(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->median(), 0);
	EXPECT_EQ(output->aggr_median().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_median(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->median(), 0);
	EXPECT_EQ(output->aggr_median().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_median(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->median(), 0);
	EXPECT_EQ(output->aggr_median().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->median(), 0);
	EXPECT_EQ(output->aggr_median().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_percentile_95)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_percentile_95(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->percentile_95(), 0);
	EXPECT_EQ(output->aggr_percentile_95().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_percentile_95(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->percentile_95(), 0);
	EXPECT_EQ(output->aggr_percentile_95().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_percentile_95(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->percentile_95(), 0);
	EXPECT_EQ(output->aggr_percentile_95().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->percentile_95(), 0);
	EXPECT_EQ(output->aggr_percentile_95().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_percentile_99)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_percentile_99(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->percentile_99(), 0);
	EXPECT_EQ(output->aggr_percentile_99().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_percentile_99(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->percentile_99(), 0);
	EXPECT_EQ(output->aggr_percentile_99().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	input->set_percentile_99(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->percentile_99(), 0);
	EXPECT_EQ(output->aggr_percentile_99().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->percentile_99(), 0);
	EXPECT_EQ(output->aggr_percentile_99().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, statsd_metric_value)
{
	message_aggregator_builder_impl builder;
	statsd_metric_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::statsd_metric;
	auto output = new draiosproto::statsd_metric;

	output->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	output->set_value(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value().sum(), 0);

	output->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	output->set_value(1);
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_HISTOGRAM);
	input->set_value(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value().sum(), 1);

	input->set_type(draiosproto::statsd_metric_type::STATSD_COUNT);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value().sum(), 3);
	delete input;
	delete output;
}

TEST(aggregator_overrides, environment)
{
	message_aggregator_builder_impl builder;
	environment_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::environment;
	auto output = new draiosproto::environment;

	output->set_hash("foo");
	output->add_variables("bar");
	output->add_variables("baz");
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->hash(), "foo");
	EXPECT_EQ(output->variables().size(), 2);

	input->set_hash("oof");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->hash(), "oof");
	EXPECT_EQ(output->variables().size(), 0);

	input->set_hash("oof");
	input->clear_variables();
	input->add_variables("biff");
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->hash(), "oof");
	EXPECT_EQ(output->variables().size(), 1);
	EXPECT_EQ(output->variables()[0], "biff");
	delete input;
	EXPECT_EQ(output->hash(), "oof");
	EXPECT_EQ(output->variables().size(), 1);
	EXPECT_EQ(output->variables()[0], "biff");
	delete output;
}

TEST(aggregator_overrides, jmx_attribute)
{
	message_aggregator_builder_impl builder;
	jmx_attribute_message_aggregator_impl aggregator(builder);

	auto input = new draiosproto::jmx_attribute;
	auto output = new draiosproto::jmx_attribute;

	output->set_value(2);
	output->add_subattributes();
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value_double().sum(), 0);

	aggregator.reset();
	output->set_value(2);
	output->clear_subattributes();
	aggregator.aggregate(*output, *output, true);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value_double().sum(), 2);

	input->set_value(2);
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value_double().sum(), 4);

	input->add_subattributes();
	aggregator.aggregate(*input, *output, false);
	EXPECT_EQ(output->value(), 0);
	EXPECT_EQ(output->aggr_value_double().sum(), 0);
	delete input;
	delete output;
}
