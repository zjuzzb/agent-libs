#include <gtest.h>
#include "draios.proto.h"
#include "draios.pb.h"
#include <iostream>
#include <fstream>
#include <gperftools/profiler.h>
#include <gperftools/heap-profiler.h>
#include <google/protobuf/util/message_differencer.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "aggregator_overrides.h"
#include "aggregator_limits.h"

TEST(aggregator_limit, statsd_metrics)
{
	message_aggregator_builder_impl builder;
	builder.set_statsd_info_statsd_metrics_limit(5);
	statsd_info_message_aggregator* aggr = new statsd_info_message_aggregator(builder);
	draiosproto::statsd_info info;
	for (uint32_t i = 0; i < 10; i++)
	{
		info.add_statsd_metrics()->mutable_aggr_sum()->set_sum(i);
	}
	statsd_info_message_aggregator::limit(builder, info);
	EXPECT_EQ(info.statsd_metrics().size(), 5);
	for (uint32_t i = 0; i < 5; i++)
	{
		EXPECT_EQ(info.statsd_metrics()[i].aggr_sum().sum(), 9 - i);
	}

	delete aggr;
}

TEST(aggregator_limit, container_top_devices)
{
	message_aggregator_builder_impl builder;
	builder.set_container_top_devices_limit(4);
	container_message_aggregator* aggr = new container_message_aggregator(builder);
	draiosproto::container input;
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(1);
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(2);
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(3);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(1);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(2);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(3);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(1);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(2);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(3);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(1);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(2);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::container input_copy = input;
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_devices().size(), 4);
	EXPECT_EQ(input_copy.top_devices()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[1].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[2].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[3].aggr_errors().sum(), 3);
	input_copy = input;
	builder.set_container_top_devices_limit(8);
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_devices().size(), 8);
	EXPECT_EQ(input_copy.top_devices()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[1].aggr_time_ns().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[2].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[3].aggr_open_count().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[4].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[5].aggr_bytes().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[6].aggr_errors().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[7].aggr_errors().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, metrics_top_devices)
{
	message_aggregator_builder_impl builder;
	builder.set_metrics_top_devices_limit(4);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(1);
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(2);
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(3);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(1);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(2);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(3);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(1);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(2);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(3);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(1);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(2);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_devices().size(), 4);
	EXPECT_EQ(input_copy.top_devices()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[1].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[2].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[3].aggr_errors().sum(), 3);
	input_copy = input;
	builder.set_metrics_top_devices_limit(8);
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_devices().size(), 8);
	EXPECT_EQ(input_copy.top_devices()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[1].aggr_time_ns().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[2].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[3].aggr_open_count().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[4].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[5].aggr_bytes().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[6].aggr_errors().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[7].aggr_errors().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, process_top_devices)
{
	message_aggregator_builder_impl builder;
	builder.set_process_top_devices_limit(4);
	process_message_aggregator* aggr = new process_message_aggregator(builder);
	draiosproto::process input;
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(1);
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(2);
	input.add_top_devices()->mutable_aggr_time_ns()->set_sum(3);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(1);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(2);
	input.add_top_devices()->mutable_aggr_open_count()->set_sum(3);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(1);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(2);
	input.add_top_devices()->mutable_aggr_bytes()->set_sum(3);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(1);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(2);
	input.add_top_devices()->mutable_aggr_errors()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::process input_copy = input;
	process_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_devices().size(), 4);
	EXPECT_EQ(input_copy.top_devices()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[1].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[2].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[3].aggr_errors().sum(), 3);
	input_copy = input;
	builder.set_process_top_devices_limit(8);
	process_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_devices().size(), 8);
	EXPECT_EQ(input_copy.top_devices()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[1].aggr_time_ns().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[2].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[3].aggr_open_count().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[4].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[5].aggr_bytes().sum(), 2);
	EXPECT_EQ(input_copy.top_devices()[6].aggr_errors().sum(), 3);
	EXPECT_EQ(input_copy.top_devices()[7].aggr_errors().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, metrics_top_files)
{
	message_aggregator_builder_impl builder;
	builder.set_metrics_top_files_limit(4);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(1);
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(2);
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(3);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(1);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(2);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(3);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(1);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(2);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(3);
	input.add_top_files()->mutable_aggr_errors()->set_sum(1);
	input.add_top_files()->mutable_aggr_errors()->set_sum(2);
	input.add_top_files()->mutable_aggr_errors()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_files().size(), 4);
	EXPECT_EQ(input_copy.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[1].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[2].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[3].aggr_errors().sum(), 3);
	input_copy = input;
	builder.set_metrics_top_files_limit(8);
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_files().size(), 8);
	EXPECT_EQ(input_copy.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[1].aggr_time_ns().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[2].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[3].aggr_open_count().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[4].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[5].aggr_bytes().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[6].aggr_errors().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[7].aggr_errors().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, container_top_files)
{
	message_aggregator_builder_impl builder;
	builder.set_container_top_files_limit(4);
	container_message_aggregator* aggr = new container_message_aggregator(builder);
	draiosproto::container input;
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(1);
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(2);
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(3);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(1);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(2);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(3);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(1);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(2);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(3);
	input.add_top_files()->mutable_aggr_errors()->set_sum(1);
	input.add_top_files()->mutable_aggr_errors()->set_sum(2);
	input.add_top_files()->mutable_aggr_errors()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::container input_copy = input;
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_files().size(), 4);
	EXPECT_EQ(input_copy.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[1].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[2].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[3].aggr_errors().sum(), 3);
	input_copy = input;
	builder.set_container_top_files_limit(8);
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_files().size(), 8);
	EXPECT_EQ(input_copy.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[1].aggr_time_ns().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[2].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[3].aggr_open_count().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[4].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[5].aggr_bytes().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[6].aggr_errors().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[7].aggr_errors().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, process_top_files)
{
	message_aggregator_builder_impl builder;
	builder.set_process_top_files_limit(4);
	process_message_aggregator* aggr = new process_message_aggregator(builder);
	draiosproto::process input;
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(1);
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(2);
	input.add_top_files()->mutable_aggr_time_ns()->set_sum(3);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(1);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(2);
	input.add_top_files()->mutable_aggr_open_count()->set_sum(3);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(1);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(2);
	input.add_top_files()->mutable_aggr_bytes()->set_sum(3);
	input.add_top_files()->mutable_aggr_errors()->set_sum(1);
	input.add_top_files()->mutable_aggr_errors()->set_sum(2);
	input.add_top_files()->mutable_aggr_errors()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::process input_copy = input;
	process_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_files().size(), 4);
	EXPECT_EQ(input_copy.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[1].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[2].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[3].aggr_errors().sum(), 3);
	input_copy = input;
	builder.set_process_top_files_limit(8);
	process_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.top_files().size(), 8);
	EXPECT_EQ(input_copy.top_files()[0].aggr_time_ns().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[1].aggr_time_ns().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[2].aggr_open_count().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[3].aggr_open_count().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[4].aggr_bytes().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[5].aggr_bytes().sum(), 2);
	EXPECT_EQ(input_copy.top_files()[6].aggr_errors().sum(), 3);
	EXPECT_EQ(input_copy.top_files()[7].aggr_errors().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_queries)
{
	message_aggregator_builder_impl builder;
	builder.set_sql_info_client_queries_limit(4);
	sql_info_message_aggregator* aggr = new sql_info_message_aggregator(builder);
	draiosproto::sql_info input;
	input.add_client_queries()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_client_queries()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_client_queries()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_client_queries()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_client_queries()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_client_queries()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_client_queries()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_client_queries()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_client_queries()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_client_queries()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_client_queries()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_client_queries()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::sql_info input_copy = input;
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_queries().size(), 4);
	EXPECT_EQ(input_copy.client_queries()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_sql_info_client_queries_limit(8);
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_queries().size(), 8);
	EXPECT_EQ(input_copy.client_queries()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.client_queries()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.client_queries()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.client_queries()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.client_queries()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_tables)
{
	message_aggregator_builder_impl builder;
	builder.set_sql_info_client_tables_limit(4);
	sql_info_message_aggregator* aggr = new sql_info_message_aggregator(builder);
	draiosproto::sql_info input;
	input.add_client_tables()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_client_tables()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_client_tables()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_client_tables()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_client_tables()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_client_tables()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_client_tables()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_client_tables()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_client_tables()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_client_tables()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_client_tables()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_client_tables()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::sql_info input_copy = input;
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_tables().size(), 4);
	EXPECT_EQ(input_copy.client_tables()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_sql_info_client_tables_limit(8);
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_tables().size(), 8);
	EXPECT_EQ(input_copy.client_tables()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.client_tables()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.client_tables()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.client_tables()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.client_tables()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, server_queries)
{
	message_aggregator_builder_impl builder;
	builder.set_sql_info_server_queries_limit(4);
	sql_info_message_aggregator* aggr = new sql_info_message_aggregator(builder);
	draiosproto::sql_info input;
	input.add_server_queries()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_server_queries()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_server_queries()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_server_queries()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_server_queries()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_server_queries()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_server_queries()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_server_queries()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_server_queries()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_server_queries()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_server_queries()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_server_queries()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::sql_info input_copy = input;
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_queries().size(), 4);
	EXPECT_EQ(input_copy.server_queries()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_sql_info_server_queries_limit(8);
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_queries().size(), 8);
	EXPECT_EQ(input_copy.server_queries()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.server_queries()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.server_queries()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.server_queries()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.server_queries()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, server_tables)
{
	message_aggregator_builder_impl builder;
	builder.set_sql_info_server_tables_limit(4);
	sql_info_message_aggregator* aggr = new sql_info_message_aggregator(builder);
	draiosproto::sql_info input;
	input.add_server_tables()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_server_tables()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_server_tables()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_server_tables()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_server_tables()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_server_tables()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_server_tables()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_server_tables()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_server_tables()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_server_tables()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_server_tables()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_server_tables()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::sql_info input_copy = input;
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_tables().size(), 4);
	EXPECT_EQ(input_copy.server_tables()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_sql_info_server_tables_limit(8);
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_tables().size(), 8);
	EXPECT_EQ(input_copy.server_tables()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.server_tables()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.server_tables()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.server_tables()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.server_tables()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, server_query_types)
{
	message_aggregator_builder_impl builder;
	builder.set_sql_info_server_query_types_limit(4);
	sql_info_message_aggregator* aggr = new sql_info_message_aggregator(builder);
	draiosproto::sql_info input;
	input.add_server_query_types()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_server_query_types()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::sql_info input_copy = input;
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_query_types().size(), 4);
	EXPECT_EQ(input_copy.server_query_types()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_sql_info_server_query_types_limit(8);
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_query_types().size(), 8);
	EXPECT_EQ(input_copy.server_query_types()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.server_query_types()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.server_query_types()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.server_query_types()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.server_query_types()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_query_types)
{
	message_aggregator_builder_impl builder;
	builder.set_sql_info_client_query_types_limit(4);
	sql_info_message_aggregator* aggr = new sql_info_message_aggregator(builder);
	draiosproto::sql_info input;
	input.add_client_query_types()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_client_query_types()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::sql_info input_copy = input;
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_query_types().size(), 4);
	EXPECT_EQ(input_copy.client_query_types()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_sql_info_client_query_types_limit(8);
	sql_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_query_types().size(), 8);
	EXPECT_EQ(input_copy.client_query_types()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.client_query_types()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.client_query_types()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.client_query_types()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.client_query_types()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_ops)
{
	message_aggregator_builder_impl builder;
	builder.set_mongodb_info_client_ops_limit(4);
	mongodb_info_message_aggregator* aggr = new mongodb_info_message_aggregator(builder);
	draiosproto::mongodb_info input;
	input.add_client_ops()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_client_ops()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_client_ops()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_client_ops()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_client_ops()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_client_ops()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_client_ops()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_client_ops()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_client_ops()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_client_ops()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_client_ops()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_client_ops()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::mongodb_info input_copy = input;
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_ops().size(), 4);
	EXPECT_EQ(input_copy.client_ops()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_mongodb_info_client_ops_limit(8);
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_ops().size(), 8);
	EXPECT_EQ(input_copy.client_ops()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.client_ops()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.client_ops()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.client_ops()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.client_ops()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, servers_ops)
{
	message_aggregator_builder_impl builder;
	builder.set_mongodb_info_servers_ops_limit(4);
	mongodb_info_message_aggregator* aggr = new mongodb_info_message_aggregator(builder);
	draiosproto::mongodb_info input;
	input.add_servers_ops()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_servers_ops()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::mongodb_info input_copy = input;
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.servers_ops().size(), 4);
	EXPECT_EQ(input_copy.servers_ops()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_mongodb_info_servers_ops_limit(8);
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.servers_ops().size(), 8);
	EXPECT_EQ(input_copy.servers_ops()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.servers_ops()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.servers_ops()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.servers_ops()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.servers_ops()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_collections)
{
	message_aggregator_builder_impl builder;
	builder.set_mongodb_info_client_collections_limit(4);
	mongodb_info_message_aggregator* aggr = new mongodb_info_message_aggregator(builder);
	draiosproto::mongodb_info input;
	input.add_client_collections()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_client_collections()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_client_collections()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_client_collections()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_client_collections()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_client_collections()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_client_collections()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_client_collections()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_client_collections()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_client_collections()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_client_collections()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_client_collections()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::mongodb_info input_copy = input;
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_collections().size(), 4);
	EXPECT_EQ(input_copy.client_collections()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_mongodb_info_client_collections_limit(8);
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_collections().size(), 8);
	EXPECT_EQ(input_copy.client_collections()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.client_collections()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.client_collections()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.client_collections()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.client_collections()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, server_collections)
{
	message_aggregator_builder_impl builder;
	builder.set_mongodb_info_server_collections_limit(4);
	mongodb_info_message_aggregator* aggr = new mongodb_info_message_aggregator(builder);
	draiosproto::mongodb_info input;
	input.add_server_collections()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_server_collections()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_server_collections()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_server_collections()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_server_collections()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_server_collections()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_server_collections()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_server_collections()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_server_collections()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_server_collections()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_server_collections()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_server_collections()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::mongodb_info input_copy = input;
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_collections().size(), 4);
	EXPECT_EQ(input_copy.server_collections()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_mongodb_info_server_collections_limit(8);
	mongodb_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_collections().size(), 8);
	EXPECT_EQ(input_copy.server_collections()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.server_collections()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.server_collections()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.server_collections()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.server_collections()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_urls)
{
	message_aggregator_builder_impl builder;
	builder.set_http_info_client_urls_limit(4);
	http_info_message_aggregator* aggr = new http_info_message_aggregator(builder);
	draiosproto::http_info input;
	input.add_client_urls()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_client_urls()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_client_urls()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_client_urls()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_client_urls()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_client_urls()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_client_urls()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_client_urls()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_client_urls()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_client_urls()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_client_urls()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_client_urls()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::http_info input_copy = input;
	http_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_urls().size(), 4);
	EXPECT_EQ(input_copy.client_urls()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_http_info_client_urls_limit(8);
	http_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_urls().size(), 8);
	EXPECT_EQ(input_copy.client_urls()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.client_urls()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.client_urls()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.client_urls()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.client_urls()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, server_urls)
{
	message_aggregator_builder_impl builder;
	builder.set_http_info_server_urls_limit(4);
	http_info_message_aggregator* aggr = new http_info_message_aggregator(builder);
	draiosproto::http_info input;
	input.add_server_urls()->mutable_counters()->mutable_aggr_time_tot()->set_sum(1);
	input.add_server_urls()->mutable_counters()->mutable_aggr_time_tot()->set_sum(2);
	input.add_server_urls()->mutable_counters()->mutable_aggr_time_tot()->set_sum(3);
	input.add_server_urls()->mutable_counters()->mutable_aggr_time_max()->set_sum(1);
	input.add_server_urls()->mutable_counters()->mutable_aggr_time_max()->set_sum(2);
	input.add_server_urls()->mutable_counters()->mutable_aggr_time_max()->set_sum(3);
	input.add_server_urls()->mutable_counters()->mutable_aggr_ncalls()->set_sum(1);
	input.add_server_urls()->mutable_counters()->mutable_aggr_ncalls()->set_sum(2);
	input.add_server_urls()->mutable_counters()->mutable_aggr_ncalls()->set_sum(3);
	input.add_server_urls()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(1);
	input.add_server_urls()->mutable_counters()->mutable_aggr_bytes_out()->set_sum(2);
	input.add_server_urls()->mutable_counters()->mutable_aggr_bytes_in()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::http_info input_copy = input;
	http_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_urls().size(), 4);
	EXPECT_EQ(input_copy.server_urls()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[1].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[2].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[3].counters().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_http_info_server_urls_limit(8);
	http_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_urls().size(), 8);
	EXPECT_EQ(input_copy.server_urls()[0].counters().aggr_time_tot().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[1].counters().aggr_time_tot().sum(), 2);
	EXPECT_EQ(input_copy.server_urls()[2].counters().aggr_time_max().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[3].counters().aggr_time_max().sum(), 2);
	EXPECT_EQ(input_copy.server_urls()[4].counters().aggr_ncalls().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[5].counters().aggr_ncalls().sum(), 2);
	EXPECT_EQ(input_copy.server_urls()[6].counters().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.server_urls()[7].counters().aggr_bytes_out().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, client_status_codes)
{
	message_aggregator_builder_impl builder;
	builder.set_http_info_client_status_codes_limit(12);
	http_info_message_aggregator* aggr = new http_info_message_aggregator(builder);
	draiosproto::http_info input;
	for (int i = 0; i < 15; i++)
	{
		input.add_client_status_codes()->mutable_aggr_ncalls()->set_sum(i);
	}

	draiosproto::http_info input_copy = input;
	http_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.client_status_codes().size(), 12);
	for (int i = 0; i < 10; i++)
	{  // biggest 10
		EXPECT_EQ(input_copy.client_status_codes()[i].aggr_ncalls().sum(), 14 - i);
	}
	for (int i = 10; i < 12; i++)
	{  // smallest 2
		EXPECT_EQ(input_copy.client_status_codes()[i].aggr_ncalls().sum(), i - 10);
	}

	delete aggr;
}

TEST(aggregator_limit, server_status_codes)
{
	message_aggregator_builder_impl builder;
	builder.set_http_info_server_status_codes_limit(12);
	http_info_message_aggregator* aggr = new http_info_message_aggregator(builder);
	draiosproto::http_info input;
	for (int i = 0; i < 15; i++)
	{
		input.add_server_status_codes()->mutable_aggr_ncalls()->set_sum(i);
	}

	draiosproto::http_info input_copy = input;
	http_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.server_status_codes().size(), 12);
	for (int i = 0; i < 10; i++)
	{  // biggest 10
		EXPECT_EQ(input_copy.server_status_codes()[i].aggr_ncalls().sum(), 14 - i);
	}
	for (int i = 10; i < 12; i++)
	{  // smallest 2
		EXPECT_EQ(input_copy.server_status_codes()[i].aggr_ncalls().sum(), i - 10);
	}

	delete aggr;
}

TEST(aggregator_limit, metrics_mounts)
{
	message_aggregator_builder_impl builder;
	builder.set_metrics_mounts_limit(4);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_mounts()->mutable_aggr_size_bytes()->set_sum(1);
	input.add_mounts()->mutable_aggr_size_bytes()->set_sum(2);
	input.add_mounts()->mutable_aggr_size_bytes()->set_sum(3);
	input.add_mounts()->mutable_aggr_available_bytes()->set_sum(1);
	input.add_mounts()->mutable_aggr_available_bytes()->set_sum(2);
	input.add_mounts()->mutable_aggr_available_bytes()->set_sum(3);
	input.add_mounts()->mutable_aggr_used_bytes()->set_sum(1);
	input.add_mounts()->mutable_aggr_used_bytes()->set_sum(2);
	input.add_mounts()->mutable_aggr_used_bytes()->set_sum(3);
	input.add_mounts()->mutable_aggr_total_inodes()->set_sum(1);
	input.add_mounts()->mutable_aggr_total_inodes()->set_sum(2);
	input.add_mounts()->mutable_aggr_total_inodes()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.mounts().size(), 4);
	EXPECT_EQ(input_copy.mounts()[0].aggr_size_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[1].aggr_available_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[2].aggr_used_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[3].aggr_total_inodes().sum(), 3);
	input_copy = input;
	builder.set_metrics_mounts_limit(8);
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.mounts().size(), 8);
	EXPECT_EQ(input_copy.mounts()[0].aggr_size_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[1].aggr_size_bytes().sum(), 2);
	EXPECT_EQ(input_copy.mounts()[2].aggr_available_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[3].aggr_available_bytes().sum(), 2);
	EXPECT_EQ(input_copy.mounts()[4].aggr_used_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[5].aggr_used_bytes().sum(), 2);
	EXPECT_EQ(input_copy.mounts()[6].aggr_total_inodes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[7].aggr_total_inodes().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, container_mounts)
{
	message_aggregator_builder_impl builder;
	builder.set_container_mounts_limit(4);
	container_message_aggregator* aggr = new container_message_aggregator(builder);
	draiosproto::container input;
	input.add_mounts()->mutable_aggr_size_bytes()->set_sum(1);
	input.add_mounts()->mutable_aggr_size_bytes()->set_sum(2);
	input.add_mounts()->mutable_aggr_size_bytes()->set_sum(3);
	input.add_mounts()->mutable_aggr_available_bytes()->set_sum(1);
	input.add_mounts()->mutable_aggr_available_bytes()->set_sum(2);
	input.add_mounts()->mutable_aggr_available_bytes()->set_sum(3);
	input.add_mounts()->mutable_aggr_used_bytes()->set_sum(1);
	input.add_mounts()->mutable_aggr_used_bytes()->set_sum(2);
	input.add_mounts()->mutable_aggr_used_bytes()->set_sum(3);
	input.add_mounts()->mutable_aggr_total_inodes()->set_sum(1);
	input.add_mounts()->mutable_aggr_total_inodes()->set_sum(2);
	input.add_mounts()->mutable_aggr_total_inodes()->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::container input_copy = input;
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.mounts().size(), 4);
	EXPECT_EQ(input_copy.mounts()[0].aggr_size_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[1].aggr_available_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[2].aggr_used_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[3].aggr_total_inodes().sum(), 3);
	input_copy = input;
	builder.set_container_mounts_limit(8);
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.mounts().size(), 8);
	EXPECT_EQ(input_copy.mounts()[0].aggr_size_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[1].aggr_size_bytes().sum(), 2);
	EXPECT_EQ(input_copy.mounts()[2].aggr_available_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[3].aggr_available_bytes().sum(), 2);
	EXPECT_EQ(input_copy.mounts()[4].aggr_used_bytes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[5].aggr_used_bytes().sum(), 2);
	EXPECT_EQ(input_copy.mounts()[6].aggr_total_inodes().sum(), 3);
	EXPECT_EQ(input_copy.mounts()[7].aggr_total_inodes().sum(), 2);

	delete aggr;
}

TEST(aggregator_limit, container_nbs)
{
	message_aggregator_builder_impl builder;
	builder.set_container_network_by_serverports_limit(2);
	container_message_aggregator* aggr = new container_message_aggregator(builder);
	draiosproto::container input;
	input.add_network_by_serverports();
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_server()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(3);
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_server()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(4);

	draiosproto::container input_copy = input;
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.network_by_serverports().size(), 2);
	EXPECT_EQ(input_copy.network_by_serverports()[0].counters().server().aggr_bytes_out().sum(), 4);
	EXPECT_EQ(input_copy.network_by_serverports()[1].counters().server().aggr_bytes_in().sum(), 3);
	builder.set_container_network_by_serverports_limit(4);
	input_copy = input;
	container_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.network_by_serverports().size(), 4);
	EXPECT_EQ(input_copy.network_by_serverports()[0].counters().server().aggr_bytes_out().sum(), 4);
	EXPECT_EQ(input_copy.network_by_serverports()[1].counters().server().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.network_by_serverports()[2].counters().client().aggr_bytes_out().sum(), 2);
	EXPECT_EQ(input_copy.network_by_serverports()[3].counters().client().aggr_bytes_in().sum(), 1);

	delete aggr;
}

TEST(aggregator_limit, host_nbs)
{
	message_aggregator_builder_impl builder;
	builder.set_host_network_by_serverports_limit(2);
	host_message_aggregator* aggr = new host_message_aggregator(builder);
	draiosproto::host input;
	input.add_network_by_serverports();
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_server()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(3);
	input.add_network_by_serverports()
	    ->mutable_counters()
	    ->mutable_server()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(4);

	draiosproto::host input_copy = input;
	host_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.network_by_serverports().size(), 2);
	EXPECT_EQ(input_copy.network_by_serverports()[0].counters().server().aggr_bytes_out().sum(), 4);
	EXPECT_EQ(input_copy.network_by_serverports()[1].counters().server().aggr_bytes_in().sum(), 3);
	builder.set_host_network_by_serverports_limit(4);
	input_copy = input;
	host_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.network_by_serverports().size(), 4);
	EXPECT_EQ(input_copy.network_by_serverports()[0].counters().server().aggr_bytes_out().sum(), 4);
	EXPECT_EQ(input_copy.network_by_serverports()[1].counters().server().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.network_by_serverports()[2].counters().client().aggr_bytes_out().sum(), 2);
	EXPECT_EQ(input_copy.network_by_serverports()[3].counters().client().aggr_bytes_in().sum(), 1);

	delete aggr;
}

TEST(aggregator_limit, pods)
{
	message_aggregator_builder_impl builder;
	builder.set_k8s_state_pods_limit(2);
	k8s_state_message_aggregator* aggr = new k8s_state_message_aggregator(builder);
	draiosproto::k8s_state input;
	input.add_pods();
	input.add_pods()->mutable_aggr_requests_cpu_cores()->set_sum(1);
	input.add_pods()->mutable_aggr_requests_cpu_cores()->set_sum(2);
	input.add_pods()->mutable_aggr_limits_cpu_cores()->set_sum(1);
	input.add_pods()->mutable_aggr_limits_cpu_cores()->set_sum(2);
	draiosproto::k8s_state input_copy = input;
	k8s_state_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.pods().size(), 2);
	EXPECT_EQ(input_copy.pods()[0].aggr_requests_cpu_cores().sum(), 2);
	EXPECT_EQ(input_copy.pods()[1].aggr_limits_cpu_cores().sum(), 2);
	delete aggr;
}

TEST(aggregator_limit, jobs)
{
	message_aggregator_builder_impl builder;
	builder.set_k8s_state_jobs_limit(1);
	k8s_state_message_aggregator* aggr = new k8s_state_message_aggregator(builder);
	draiosproto::k8s_state input;
	input.add_jobs();
	input.add_jobs()->mutable_aggr_completions()->set_sum(1);
	input.add_jobs()->mutable_aggr_completions()->set_sum(2);
	draiosproto::k8s_state input_copy = input;
	k8s_state_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.jobs().size(), 1);
	EXPECT_EQ(input_copy.jobs()[0].aggr_completions().sum(), 2);
	delete aggr;
}

TEST(aggregator_limit, app_metric)
{
	message_aggregator_builder_impl builder;
	builder.set_app_info_metrics_limit(5);
	app_info_message_aggregator* aggr = new app_info_message_aggregator(builder);
	draiosproto::app_info input;
	for (int i = 0; i < 15; i++)
	{
		input.add_metrics()->mutable_aggr_value_double()->set_sum(i);
	}

	draiosproto::app_info input_copy = input;
	app_info_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.metrics().size(), 5);
	for (int i = 0; i < 5; i++)
	{
		EXPECT_EQ(input_copy.metrics()[i].aggr_value_double().sum(), 14 - i);
	}

	delete aggr;
}

TEST(aggregator_limit, events)
{
	message_aggregator_builder_impl builder;
	builder.set_metrics_events_limit(5);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	for (int i = 0; i < 15; i++)
	{
		input.add_events()->set_timestamp_sec(i);
	}

	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.events().size(), 5);
	for (int i = 0; i < 5; i++)
	{
		EXPECT_EQ(input_copy.events()[i].timestamp_sec(), i);
	}

	delete aggr;
}

TEST(aggregator_limit, incomplete_connections)
{
	message_aggregator_builder_impl builder;
	builder.set_metrics_ipv4_incomplete_connections_v2_limit(4);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_server()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(3);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(1);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->mutable_aggr_count_out()
	    ->set_sum(2);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(3);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_min_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(1);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_min_transaction_counters()
	    ->mutable_aggr_count_out()
	    ->set_sum(2);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_min_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(3);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(1);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->mutable_aggr_count_out()
	    ->set_sum(2);
	input.add_ipv4_incomplete_connections_v2()
	    ->mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2().size(), 4);
	EXPECT_EQ(
	    input_copy.ipv4_incomplete_connections_v2()[0].counters().client().aggr_bytes_out().sum(),
	    3);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[1]
	              .counters()
	              .transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          3);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[2]
	              .counters()
	              .min_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          1);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[3]
	              .counters()
	              .max_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          3);
	builder.set_metrics_ipv4_incomplete_connections_v2_limit(8);
	input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2().size(), 8);
	EXPECT_EQ(
	    input_copy.ipv4_incomplete_connections_v2()[0].counters().client().aggr_bytes_out().sum(),
	    3);
	EXPECT_EQ(
	    input_copy.ipv4_incomplete_connections_v2()[1].counters().server().aggr_bytes_out().sum(),
	    2);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[2]
	              .counters()
	              .transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          3);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[3]
	              .counters()
	              .transaction_counters()
	              .aggr_count_out()
	              .sum(),
	          2);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[4]
	              .counters()
	              .min_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          1);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[5]
	              .counters()
	              .min_transaction_counters()
	              .aggr_count_out()
	              .sum(),
	          2);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[6]
	              .counters()
	              .max_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          3);
	EXPECT_EQ(input_copy.ipv4_incomplete_connections_v2()[7]
	              .counters()
	              .max_transaction_counters()
	              .aggr_count_out()
	              .sum(),
	          2);

	delete aggr;
}

TEST(aggregator_limit, connections)
{
	message_aggregator_builder_impl builder;
	builder.set_metrics_ipv4_connections_limit(4);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_server()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_client()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(3);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(1);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->mutable_aggr_count_out()
	    ->set_sum(2);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(3);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_min_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(1);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_min_transaction_counters()
	    ->mutable_aggr_count_out()
	    ->set_sum(2);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_min_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(3);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(1);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->mutable_aggr_count_out()
	    ->set_sum(2);
	input.add_ipv4_connections()
	    ->mutable_counters()
	    ->mutable_max_transaction_counters()
	    ->mutable_aggr_count_in()
	    ->set_sum(3);

	// for better or worse, this will enforce the ordering instead of just the contents,
	// which is stricter than it needs to be, but it's a pain in the neck to do it that
	// way
	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.ipv4_connections().size(), 4);
	EXPECT_EQ(input_copy.ipv4_connections()[0].counters().client().aggr_bytes_out().sum(), 3);
	EXPECT_EQ(
	    input_copy.ipv4_connections()[1].counters().transaction_counters().aggr_count_in().sum(),
	    3);
	EXPECT_EQ(input_copy.ipv4_connections()[2]
	              .counters()
	              .min_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          1);
	EXPECT_EQ(input_copy.ipv4_connections()[3]
	              .counters()
	              .max_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          3);
	builder.set_metrics_ipv4_connections_limit(8);
	input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.ipv4_connections().size(), 8);
	EXPECT_EQ(input_copy.ipv4_connections()[0].counters().client().aggr_bytes_out().sum(), 3);
	EXPECT_EQ(input_copy.ipv4_connections()[1].counters().server().aggr_bytes_out().sum(), 2);
	EXPECT_EQ(
	    input_copy.ipv4_connections()[2].counters().transaction_counters().aggr_count_in().sum(),
	    3);
	EXPECT_EQ(
	    input_copy.ipv4_connections()[3].counters().transaction_counters().aggr_count_out().sum(),
	    2);
	EXPECT_EQ(input_copy.ipv4_connections()[4]
	              .counters()
	              .min_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          1);
	EXPECT_EQ(input_copy.ipv4_connections()[5]
	              .counters()
	              .min_transaction_counters()
	              .aggr_count_out()
	              .sum(),
	          2);
	EXPECT_EQ(input_copy.ipv4_connections()[6]
	              .counters()
	              .max_transaction_counters()
	              .aggr_count_in()
	              .sum(),
	          3);
	EXPECT_EQ(input_copy.ipv4_connections()[7]
	              .counters()
	              .max_transaction_counters()
	              .aggr_count_out()
	              .sum(),
	          2);

	delete aggr;
}

TEST(aggregator_limit, containers)
{
	// first stuff, we'll not worry about the priority containers
	message_aggregator_builder_impl builder;
	builder.set_metrics_containers_limit(4);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_containers()->mutable_resource_counters()->mutable_aggr_cpu_pct()->set_sum(1);
	input.add_containers()->mutable_resource_counters()->mutable_aggr_cpu_pct()->set_sum(2);
	input.add_containers()->mutable_resource_counters()->mutable_aggr_cpu_pct()->set_sum(3);
	input.add_containers()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(1);
	input.add_containers()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(2);
	input.add_containers()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(3);
	input.add_containers()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_containers()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_containers()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_other()
	    ->set_sum(3);
	input.add_containers()
	    ->mutable_tcounters()
	    ->mutable_io_net()
	    ->mutable_aggr_bytes_other()
	    ->set_sum(1);
	input.add_containers()
	    ->mutable_tcounters()
	    ->mutable_io_net()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_containers()->mutable_tcounters()->mutable_io_net()->mutable_aggr_bytes_in()->set_sum(
	    3);

	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.containers().size(), 4);
	EXPECT_EQ(input_copy.containers()[0].resource_counters().aggr_cpu_pct().sum(), 3);
	EXPECT_EQ(input_copy.containers()[1].resource_counters().aggr_resident_memory_usage_kb().sum(),
	          3);
	EXPECT_EQ(input_copy.containers()[2].tcounters().io_file().aggr_bytes_other().sum(), 3);
	EXPECT_EQ(input_copy.containers()[3].tcounters().io_net().aggr_bytes_in().sum(), 3);
	input_copy = input;
	builder.set_metrics_containers_limit(8);
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.containers().size(), 8);
	EXPECT_EQ(input_copy.containers()[0].resource_counters().aggr_cpu_pct().sum(), 3);
	EXPECT_EQ(input_copy.containers()[1].resource_counters().aggr_cpu_pct().sum(), 2);
	EXPECT_EQ(input_copy.containers()[2].resource_counters().aggr_resident_memory_usage_kb().sum(),
	          3);
	EXPECT_EQ(input_copy.containers()[3].resource_counters().aggr_resident_memory_usage_kb().sum(),
	          2);
	EXPECT_EQ(input_copy.containers()[4].tcounters().io_file().aggr_bytes_other().sum(), 3);
	EXPECT_EQ(input_copy.containers()[5].tcounters().io_file().aggr_bytes_out().sum(), 2);
	EXPECT_EQ(input_copy.containers()[6].tcounters().io_net().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.containers()[7].tcounters().io_net().aggr_bytes_out().sum(), 2);

	// next stuff, ensure we get priority containers
	input.clear_containers();
	builder.set_metrics_containers_limit(6);
	input.add_containers()->mutable_resource_counters()->mutable_aggr_cpu_pct()->set_sum(3);
	input.add_containers()->mutable_resource_counters()->mutable_aggr_cpu_pct()->set_sum(1);
	input.add_containers()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(1);
	input.add_containers()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_containers()->mutable_tcounters()->mutable_io_net()->mutable_aggr_bytes_in()->set_sum(
	    1);
	input.add_containers()->add_container_reporting_group_id(1);
	input.add_containers()->add_container_reporting_group_id(1);
	input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.containers().size(), 6);
	EXPECT_EQ(input_copy.containers()[0].container_reporting_group_id().size(), 1);
	EXPECT_EQ(input_copy.containers()[1].container_reporting_group_id().size(), 1);
	EXPECT_EQ(input_copy.containers()[2].resource_counters().aggr_cpu_pct().sum(), 3);
	EXPECT_EQ(input_copy.containers()[3].resource_counters().aggr_resident_memory_usage_kb().sum(),
	          1);
	EXPECT_EQ(input_copy.containers()[4].tcounters().io_file().aggr_bytes_in().sum(), 1);
	EXPECT_EQ(input_copy.containers()[5].tcounters().io_net().aggr_bytes_in().sum(), 1);

	// limit below number of priority containers
	builder.set_metrics_containers_limit(1);
	input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.containers().size(), 1);
	EXPECT_EQ(input_copy.containers()[0].container_reporting_group_id().size(), 1);

	delete aggr;
}

TEST(aggregator_limit, programs)
{
	// first stuff, we'll not worry about the priority programs
	message_aggregator_builder_impl builder;
	builder.set_metrics_programs_limit(5);
	metrics_message_aggregator* aggr = new metrics_message_aggregator(builder);
	draiosproto::metrics input;
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_cpu_pct()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_cpu_pct()
	    ->set_sum(2);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_cpu_pct()
	    ->set_sum(3);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(2);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(3);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_other()
	    ->set_sum(3);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_net()
	    ->mutable_aggr_bytes_other()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_net()
	    ->mutable_aggr_bytes_out()
	    ->set_sum(2);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_net()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(3);
	input.add_programs()->mutable_procinfo()->mutable_protos()->mutable_app()->add_metrics();
	input.add_programs()->mutable_procinfo()->mutable_protos()->mutable_prometheus()->add_metrics();
	for (int i = 0; i < input.programs().size(); i++)
	{
		(*input.mutable_programs())[i].add_pids(i);
	}

	draiosproto::metrics input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.programs().size(), 5);
	EXPECT_EQ(input_copy.programs()[0].procinfo().resource_counters().aggr_cpu_pct().sum(), 3);
	EXPECT_EQ(input_copy.programs()[1]
	              .procinfo()
	              .resource_counters()
	              .aggr_resident_memory_usage_kb()
	              .sum(),
	          3);
	EXPECT_EQ(input_copy.programs()[2].procinfo().tcounters().io_file().aggr_bytes_other().sum(),
	          3);
	EXPECT_EQ(input_copy.programs()[3].procinfo().tcounters().io_net().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.programs()[4].procinfo().protos().app().metrics().size(), 1);
	input_copy = input;
	builder.set_metrics_programs_limit(10);
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.programs().size(), 10);
	EXPECT_EQ(input_copy.programs()[0].procinfo().resource_counters().aggr_cpu_pct().sum(), 3);
	EXPECT_EQ(input_copy.programs()[1].procinfo().resource_counters().aggr_cpu_pct().sum(), 2);
	EXPECT_EQ(input_copy.programs()[2]
	              .procinfo()
	              .resource_counters()
	              .aggr_resident_memory_usage_kb()
	              .sum(),
	          3);
	EXPECT_EQ(input_copy.programs()[3]
	              .procinfo()
	              .resource_counters()
	              .aggr_resident_memory_usage_kb()
	              .sum(),
	          2);
	EXPECT_EQ(input_copy.programs()[4].procinfo().tcounters().io_file().aggr_bytes_other().sum(),
	          3);
	EXPECT_EQ(input_copy.programs()[5].procinfo().tcounters().io_file().aggr_bytes_out().sum(), 2);
	EXPECT_EQ(input_copy.programs()[6].procinfo().tcounters().io_net().aggr_bytes_in().sum(), 3);
	EXPECT_EQ(input_copy.programs()[7].procinfo().tcounters().io_net().aggr_bytes_out().sum(), 2);
	EXPECT_EQ(input_copy.programs()[8].procinfo().protos().app().metrics().size(), 1);
	EXPECT_EQ(input_copy.programs()[9].procinfo().protos().prometheus().metrics().size(), 1);

	// next stuff, ensure we get priority programs
	input.clear_programs();
	builder.set_metrics_programs_limit(7);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_cpu_pct()
	    ->set_sum(3);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_cpu_pct()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_resource_counters()
	    ->mutable_aggr_resident_memory_usage_kb()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_file()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_programs()
	    ->mutable_procinfo()
	    ->mutable_tcounters()
	    ->mutable_io_net()
	    ->mutable_aggr_bytes_in()
	    ->set_sum(1);
	input.add_programs()->mutable_procinfo()->mutable_protos()->mutable_prometheus()->add_metrics();
	input.add_programs()->add_program_reporting_group_id(1);
	input.add_programs()->add_program_reporting_group_id(1);
	for (int i = 0; i < input.programs().size(); i++)
	{
		(*input.mutable_programs())[i].add_pids(i);
	}

	input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.programs().size(), 7);
	EXPECT_EQ(input_copy.programs()[0].program_reporting_group_id().size(), 1);
	EXPECT_EQ(input_copy.programs()[1].program_reporting_group_id().size(), 1);
	EXPECT_EQ(input_copy.programs()[2].procinfo().resource_counters().aggr_cpu_pct().sum(), 3);
	EXPECT_EQ(input_copy.programs()[3]
	              .procinfo()
	              .resource_counters()
	              .aggr_resident_memory_usage_kb()
	              .sum(),
	          1);
	EXPECT_EQ(input_copy.programs()[4].procinfo().tcounters().io_file().aggr_bytes_in().sum(), 1);
	EXPECT_EQ(input_copy.programs()[5].procinfo().tcounters().io_net().aggr_bytes_in().sum(), 1);
	EXPECT_EQ(input_copy.programs()[6].procinfo().protos().prometheus().metrics().size(), 1);

	// limit below number of priority programs
	builder.set_metrics_programs_limit(1);
	input_copy = input;
	metrics_message_aggregator::limit(builder, input_copy);
	EXPECT_EQ(input_copy.programs().size(), 1);
	EXPECT_EQ(input_copy.programs()[0].program_reporting_group_id().size(), 1);

	delete aggr;
}

