#include "async_aggregator.h"
#include "analyzer_utils.h" // make_unique
#include "scoped_config.h"
#include "watchdog_runnable_pool.h"
#include "draios.pb.h"
#include <gtest.h>
#include <iostream>

class test_helper
{
public:
	static uint32_t get_flush_interval(dragent::async_aggregator& aggregator)
	{
		return aggregator.m_aggregation_interval;
	}
	static uint32_t get_count_since_flush(dragent::async_aggregator& aggregator)
	{
		return aggregator.m_count_since_flush;
	}

};

// make sure pushing a single PB through the aggregator works
TEST(async_aggregator, single)
{
	dragent::async_aggregator::queue_t input_queue(10);
	dragent::async_aggregator::queue_t output_queue(10);

	dragent::async_aggregator aggregator(input_queue,
										 output_queue,
										 // stupid short timeout because aint nobody got time for waiting for cleanup!
										 1,
										 "");
	dragent::watchdog_runnable_pool pool;
	pool.start(aggregator, 10);
	std::atomic<bool> sent_metrics(false);

	draiosproto::metrics input;
	std::string machine_id = "zipperbox";
	input.set_machine_id(machine_id);

	input_queue.put(std::make_shared<flush_data_message>(
		1,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(output_queue.size(), 1);
	std::shared_ptr<flush_data_message> output;
	bool ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_ts, 1);
	EXPECT_EQ(output->m_metrics_sent, &sent_metrics);
	EXPECT_EQ(output->m_metrics->machine_id(), machine_id);

	// not applicable to aggregated output
	EXPECT_EQ(output->m_nevts, 0);
	EXPECT_EQ(output->m_num_drop_events, 0);
	EXPECT_EQ(output->m_my_cpuload, 0);
	EXPECT_EQ(output->m_sampling_ratio, 0);
	EXPECT_EQ(output->m_n_tids_suppressed, 0);

	aggregator.stop();
	pool.stop_all();
}

// make sure pushing two PBs aggregates them correctly
TEST(async_aggregator, multiple)
{
	test_helpers::scoped_config<unsigned int> config("aggregator.aggregation_interval", 2);

	dragent::async_aggregator::queue_t input_queue(10);
	dragent::async_aggregator::queue_t output_queue(10);

	dragent::async_aggregator aggregator(input_queue,
										 output_queue,
										 // stupid short timeout because aint nobody got time for waiting for cleanup!
										 1,
										 "");
	dragent::watchdog_runnable_pool pool;
	pool.start(aggregator, 1);
	std::atomic<bool> sent_metrics(false);

	draiosproto::metrics input;
	input.set_sampling_ratio(1);

	uint32_t timestamp = 1 * NSECS_PER_SEC;
	input_queue.put(std::make_shared<flush_data_message>(
		timestamp,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields

	input.set_sampling_ratio(2);
	input_queue.put(std::make_shared<flush_data_message>(
		timestamp + 1 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields

	// sleep 
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(output_queue.size(), 1);
	std::shared_ptr<flush_data_message> output;
	bool ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_ts, timestamp + 1 * NSECS_PER_SEC); // should get second timestamp
	EXPECT_EQ(output->m_metrics_sent, &sent_metrics);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().sum(), 3);

	// not applicable to aggregated output
	EXPECT_EQ(output->m_nevts, 0);
	EXPECT_EQ(output->m_num_drop_events, 0);
	EXPECT_EQ(output->m_my_cpuload, 0);
	EXPECT_EQ(output->m_sampling_ratio, 0);
	EXPECT_EQ(output->m_n_tids_suppressed, 0);

	aggregator.stop();
	pool.stop_all();
}

// make sure the aggregator still works on the second aggregation after outputing (i.e.
// the output PB gets cleared
TEST(async_aggregator, followup_aggregation)
{
	dragent::async_aggregator::queue_t input_queue(10);
	dragent::async_aggregator::queue_t output_queue(10);

	dragent::async_aggregator aggregator(input_queue,
										 output_queue,
										 // stupid short timeout because aint nobody got time for waiting for cleanup!
										 1,
										 "");
	dragent::watchdog_runnable_pool pool;
	pool.start(aggregator, 1);
	std::atomic<bool> sent_metrics(false);

	draiosproto::metrics input;
	input.set_sampling_ratio(1);

	input_queue.put(std::make_shared<flush_data_message>(
		0,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields

	input.set_sampling_ratio(2);
	input_queue.put(std::make_shared<flush_data_message>(
		1,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields

	for (uint32_t i = 0; output_queue.size() != 2 && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(output_queue.size(), 2);
	std::shared_ptr<flush_data_message> output;
	bool ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_ts, 0);
	EXPECT_EQ(output->m_metrics_sent, &sent_metrics);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().sum(), 1);

	ASSERT_EQ(output_queue.size(), 1);
	ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_ts, 1);
	EXPECT_EQ(output->m_metrics_sent, &sent_metrics);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().sum(), 2);

	aggregator.stop();
	pool.stop_all();
}

// make sure the limiter works
TEST(async_aggregator, limiter)
{
	dragent::async_aggregator::queue_t input_queue(10);
	dragent::async_aggregator::queue_t output_queue(10);

	dragent::async_aggregator aggregator(input_queue,
										 output_queue,
										 // stupid short timeout because aint nobody got time for waiting for cleanup!
										 1,
										 "");

	// check that we have default limit
	EXPECT_EQ(dragent::aggregator_limits::global_limits->m_containers, UINT32_MAX);
	EXPECT_EQ(dragent::aggregator_limits::global_limits->m_jmx, UINT32_MAX);
	// try setting the limit via a message
	draiosproto::aggregation_context ac;
	ac.mutable_metr_limits()->set_jmx(1);
	ac.mutable_metr_limits()->set_prom_metrics_weight(.1);
	ac.mutable_metr_limits()->set_containers(5);
	ac.set_enforce(true);
	dragent::aggregator_limits::global_limits->cache_limits(ac);
	EXPECT_EQ(dragent::aggregator_limits::global_limits->m_jmx, 1);
	EXPECT_EQ(dragent::aggregator_limits::global_limits->m_containers, 5);

	dragent::watchdog_runnable_pool pool;
	pool.start(aggregator, 10);
	std::atomic<bool> sent_metrics(false);

	draiosproto::metrics input;
	std::string machine_id = "zipperbox";
	input.set_machine_id(machine_id);
	for(int i = 0; i < 20; i++)
	{
		auto container = input.add_containers();
		container->set_id(std::to_string(i));
	}

	input_queue.put(std::make_shared<flush_data_message>(
		0,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(output_queue.size(), 1);
	std::shared_ptr<flush_data_message> output;
	bool ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_metrics->containers().size(), 5);

	// double check the one-off config based limit twiddleable got set properly during
	// limiting
	EXPECT_EQ(configuration_manager::instance().get_config<double>("aggregator.prom_metrics_weight")->get_value(), .1);
	
	aggregator.stop();
	pool.stop_all();
	// we twiddled the global limit state, so reset it
	dragent::aggregator_limits::global_limits = std::make_shared<dragent::aggregator_limits>();
}

TEST(async_aggregator, count_jmx_attributes)
{
	draiosproto::jmx_attribute attr;
	EXPECT_EQ(dragent::async_aggregator::count_attributes(attr), 1);
	attr.add_subattributes();
	attr.add_subattributes();
	EXPECT_EQ(dragent::async_aggregator::count_attributes(attr), 3);
	attr.add_subattributes()->add_subattributes();
	EXPECT_EQ(dragent::async_aggregator::count_attributes(attr), 5);
}

TEST(async_aggregator, limit_jmx_attributes_helper)
{
	// first time, get limit so it falls exactly on a bean boundary
	draiosproto::java_info ji;
	ji.add_beans()->add_attributes();
	ji.add_beans()->add_attributes()->add_subattributes();
	ji.add_beans()->add_attributes()->add_subattributes()->add_subattributes();
	int64_t remaining = 3;
	dragent::async_aggregator::limit_jmx_attributes_helper(ji, remaining);
	EXPECT_EQ(ji.beans().size(), 3);
	EXPECT_EQ(remaining, 0);
	EXPECT_EQ(ji.beans()[0].attributes().size(), 1);
	EXPECT_EQ(ji.beans()[1].attributes()[0].subattributes().size(), 1);
	EXPECT_EQ(ji.beans()[1].attributes()[0].subattributes()[0].subattributes().size(), 0);
	EXPECT_EQ(ji.beans()[2].attributes().size(), 0);
	ji.add_beans()->add_attributes()->add_subattributes()->add_subattributes();
	ji.add_beans()->add_attributes()->add_subattributes()->add_subattributes();
	remaining = 5;
	dragent::async_aggregator::limit_jmx_attributes_helper(ji, remaining);
	EXPECT_EQ(ji.beans().size(), 5);
	EXPECT_EQ(remaining, -1);
	EXPECT_EQ(ji.beans()[0].attributes().size(), 1);
	EXPECT_EQ(ji.beans()[1].attributes()[0].subattributes().size(), 1);
	EXPECT_EQ(ji.beans()[1].attributes()[0].subattributes()[0].subattributes().size(), 0);
	EXPECT_EQ(ji.beans()[2].attributes().size(), 0);
	EXPECT_EQ(ji.beans()[3].attributes()[0].subattributes().size(), 1);
	EXPECT_EQ(ji.beans()[3].attributes()[0].subattributes()[0].subattributes().size(), 1);
	EXPECT_EQ(ji.beans()[3].attributes()[0].subattributes()[0].subattributes()[0].subattributes().size(), 0);
	EXPECT_EQ(ji.beans()[4].attributes().size(), 0);
}

TEST(async_aggregator, limit_jmx_attributes)
{
	draiosproto::metrics metrics;

	// add some beans and stuff and make sure as we decrease the limit, they
	// fall off appropriately
	metrics.mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.mutable_unreported_counters()->mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.mutable_unreported_counters()->mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.add_programs()->mutable_procinfo()->mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.add_programs()->mutable_procinfo()->mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.add_containers()->mutable_protos()->mutable_java()->add_beans()->add_attributes();
	metrics.add_containers()->mutable_protos()->mutable_java()->add_beans()->add_attributes();

	dragent::async_aggregator::limit_jmx_attributes(metrics, 7);
	EXPECT_EQ(metrics.containers()[0].protos().java().beans()[0].attributes().size(), 1);
	EXPECT_EQ(metrics.containers()[1].protos().java().beans()[0].attributes().size(), 0);
	dragent::async_aggregator::limit_jmx_attributes(metrics, 5);
	EXPECT_EQ(metrics.programs()[0].procinfo().protos().java().beans()[0].attributes().size(), 1);
	EXPECT_EQ(metrics.programs()[1].procinfo().protos().java().beans()[0].attributes().size(), 0);
	dragent::async_aggregator::limit_jmx_attributes(metrics, 3);
	EXPECT_EQ(metrics.unreported_counters().protos().java().beans()[0].attributes().size(), 1);
	EXPECT_EQ(metrics.unreported_counters().protos().java().beans()[1].attributes().size(), 0);
	dragent::async_aggregator::limit_jmx_attributes(metrics, 1);
	EXPECT_EQ(metrics.protos().java().beans()[0].attributes().size(), 1);
	EXPECT_EQ(metrics.protos().java().beans()[1].attributes().size(), 0);
}
	
// make sure the post-aggregate substitutions are happening
TEST(async_aggregator, substitutions)
{
	dragent::async_aggregator::queue_t input_queue(10);
	dragent::async_aggregator::queue_t output_queue(10);

	dragent::async_aggregator aggregator(input_queue,
										 output_queue,
										 // stupid short timeout because aint nobody got time for waiting for cleanup!
										 1,
										 "");
	dragent::watchdog_runnable_pool pool;
	pool.start(aggregator, 10);
	std::atomic<bool> sent_metrics(false);

	draiosproto::metrics input;
	auto proc = input.add_programs();
	proc->mutable_procinfo()->mutable_details()->set_comm("wrong");
	proc->mutable_procinfo()->mutable_details()->set_exe("something just to make the hash different");
	proc->mutable_procinfo()->mutable_protos()->mutable_java()->set_process_name("right");
	uint64_t spid = 8675309;
	proc->add_pids(spid);
	uint64_t dpid = 1337;
	input.add_programs()->add_pids(dpid);
	auto conn = input.add_ipv4_connections();
	conn->set_spid(spid);
	conn->set_dpid(dpid);
	conn->set_state(draiosproto::connection_state::CONN_SUCCESS);
	auto iconn = input.add_ipv4_incomplete_connections_v2();
	iconn->set_spid(spid);
	iconn->set_dpid(dpid);
	iconn->set_state(draiosproto::connection_state::CONN_FAILED);

	input_queue.put(std::make_shared<flush_data_message>(
		0,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5
	)); // random numbers since we don't propagate those fields
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}

	ASSERT_EQ(output_queue.size(), 1);
	std::shared_ptr<flush_data_message> output;
	bool ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_metrics->programs().size(), 2);
	EXPECT_EQ(output->m_metrics->programs()[0].procinfo().details().comm(), "right");
	EXPECT_EQ(output->m_metrics->programs()[0].pids().size(), 1);
	EXPECT_EQ(output->m_metrics->programs()[0].pids()[0],
			  metrics_message_aggregator_impl::program_java_hasher(output->m_metrics->programs()[0]));
	EXPECT_EQ(output->m_metrics->programs()[1].pids()[0],
			  metrics_message_aggregator_impl::program_java_hasher(output->m_metrics->programs()[1]));
	EXPECT_EQ(output->m_metrics->ipv4_connections().size(), 1);
	EXPECT_EQ(output->m_metrics->ipv4_connections()[0].spid(),
			  output->m_metrics->programs()[0].pids()[0]);
	EXPECT_EQ(output->m_metrics->ipv4_connections()[0].dpid(),
			  output->m_metrics->programs()[1].pids()[0]);
	EXPECT_EQ(output->m_metrics->ipv4_incomplete_connections_v2().size(), 1);
	EXPECT_EQ(output->m_metrics->ipv4_incomplete_connections_v2()[0].spid(),
			  output->m_metrics->programs()[0].pids()[0]);
	EXPECT_EQ(output->m_metrics->ipv4_incomplete_connections_v2()[0].dpid(),
			  output->m_metrics->programs()[1].pids()[0]);
	
	aggregator.stop();
	pool.stop_all();
}

TEST(async_aggregator, relocate_prom_metrics)
{
	draiosproto::proto_info pi;
	pi.mutable_prom_info()->set_process_name("process");
	auto i = pi.mutable_prom_info()->add_metrics();
	i->set_name("metric 1");
	i = pi.mutable_prom_info()->add_metrics();
	i->set_name("metric 2");
	i->set_type(draiosproto::app_metric_type::APP_METRIC_TYPE_PROMETHEUS_RAW);
	i->set_value(2);
	i->mutable_aggr_value_double()->set_sum(3);
	i->add_tags()->set_key("some key");
	i->add_buckets()->set_count(4);
	i->set_prometheus_type(draiosproto::prometheus_type::PROMETHEUS_TYPE_GAUGE);

	dragent::async_aggregator::relocate_prom_metrics(pi);
	EXPECT_EQ(pi.prometheus().process_name(), "process");
	ASSERT_EQ(pi.prometheus().metrics().size(), 2);
	EXPECT_EQ(pi.prometheus().metrics()[0].name(), "metric 1");
	EXPECT_EQ(pi.prometheus().metrics()[1].type(), draiosproto::app_metric_type::APP_METRIC_TYPE_PROMETHEUS_RAW);
	EXPECT_EQ(pi.prometheus().metrics()[1].value(), 2);
	EXPECT_EQ(pi.prometheus().metrics()[1].aggr_value_double().sum(), 3);
	EXPECT_EQ(pi.prometheus().metrics()[1].tags()[0].key(), "some key");
	EXPECT_EQ(pi.prometheus().metrics()[1].buckets()[0].count(), 4);
	EXPECT_EQ(pi.prometheus().metrics()[1].prometheus_type(), draiosproto::prometheus_type::PROMETHEUS_TYPE_GAUGE);
}

TEST(async_aggregator, relocate_moved_fields)
{
	draiosproto::metrics m;
	auto i = m.add_ipv4_incomplete_connections_v2();
	i->mutable_tuple()->set_sip(1);
	i->set_spid(2);
	i->set_dpid(3);
	i->mutable_counters()->set_n_aggregated_connections(4);
	i->set_state(draiosproto::connection_state::CONN_FAILED);
	i->set_error_code(draiosproto::error_code::ERR_ECHILD);

	m.mutable_protos()->mutable_prom_info()->set_process_name("5");
	m.mutable_unreported_counters()->mutable_protos()->mutable_prom_info()->set_process_name("6");
	m.add_containers()->mutable_protos()->mutable_prom_info()->set_process_name("7");
	m.add_programs()->mutable_procinfo()->mutable_protos()->mutable_prom_info()->set_process_name("8");

	dragent::async_aggregator::relocate_moved_fields(m);
	ASSERT_EQ(m.ipv4_incomplete_connections().size(), 1);
	EXPECT_EQ(m.ipv4_incomplete_connections()[0].tuple().sip(), 1);
	EXPECT_EQ(m.ipv4_incomplete_connections()[0].spid(), 2);
	EXPECT_EQ(m.ipv4_incomplete_connections()[0].dpid(), 3);
	EXPECT_EQ(m.ipv4_incomplete_connections()[0].counters().n_aggregated_connections(), 4);
	EXPECT_EQ(m.ipv4_incomplete_connections()[0].state(), draiosproto::connection_state::CONN_FAILED);
	EXPECT_EQ(m.ipv4_incomplete_connections()[0].error_code(), draiosproto::error_code::ERR_ECHILD);
	EXPECT_EQ(m.protos().prometheus().process_name(), "5");
	EXPECT_EQ(m.unreported_counters().protos().prometheus().process_name(), "6");
	EXPECT_EQ(m.containers()[0].protos().prometheus().process_name(), "7");
	EXPECT_EQ(m.programs()[0].procinfo().protos().prometheus().process_name(), "8");
}

// note: can't just wait for queue size here as possibility of race if
// we pop from queue and then update aggregation_interval before it's read by the aggr
// thread
void wait_aggr(dragent::async_aggregator& aggr, uint32_t count)
{
	for (uint32_t i = 0; test_helper::get_count_since_flush(aggr) != count && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(test_helper::get_count_since_flush(aggr), count);
}

TEST(async_aggregator, flush_interval_zero)
{
	test_helpers::scoped_config<uint32_t> config("aggregator.aggregation_interval", 5);
	dragent::async_aggregator::queue_t input_queue(10);
	dragent::async_aggregator::queue_t output_queue(10);

	dragent::async_aggregator aggregator(input_queue,
										 output_queue,
										 // stupid short timeout because aint nobody got time for waiting for cleanup!
										 1,
										 "");

	dragent::watchdog_runnable_pool pool;
	pool.start(aggregator, 10);

	EXPECT_EQ(test_helper::get_flush_interval(aggregator), 5);
	aggregator.set_aggregation_interval(4);
	EXPECT_EQ(test_helper::get_flush_interval(aggregator), 4);
	aggregator.set_aggregation_interval(0);


	draiosproto::metrics input;

	// check that no aggregation works
	std::atomic<bool> sent_metrics(false);
	input.set_sampling_ratio(1);
	input_queue.put(std::make_shared<flush_data_message>(
		1,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(output_queue.size(), 1);
	std::shared_ptr<flush_data_message> output;
	bool ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_flush_interval, 0);
	EXPECT_EQ(output->m_metrics->sampling_ratio(), 1);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().weight(), 0);

	// check that switching to zero while aggregation in flight works
	aggregator.set_aggregation_interval(2);
	input.set_sampling_ratio(2);
	input_queue.put(std::make_shared<flush_data_message>(
		1 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	wait_aggr(aggregator, 1);
	aggregator.set_aggregation_interval(0);
	input.set_sampling_ratio(3);
	input_queue.put(std::make_shared<flush_data_message>(
		2 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(output_queue.size(), 1);
	ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_flush_interval, 0);
	EXPECT_EQ(output->m_metrics->sampling_ratio(), 3);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().weight(), 0);

	// check that we can aggregate after the above scenario
	aggregator.set_aggregation_interval(2);
	input.set_sampling_ratio(4);
	input_queue.put(std::make_shared<flush_data_message>(
		1 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	input.set_sampling_ratio(5);
	input_queue.put(std::make_shared<flush_data_message>(
		2 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(output_queue.size(), 1);
	ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_flush_interval, 2);
	EXPECT_EQ(output->m_metrics->sampling_ratio(), 4);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().sum(), 9);

	// check that if we increase aggregation interval while aggregation in flight, it works
	input.set_sampling_ratio(6);
	input_queue.put(std::make_shared<flush_data_message>(
		1 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	wait_aggr(aggregator, 1);
	aggregator.set_aggregation_interval(3);
	input.set_sampling_ratio(7);
	input_queue.put(std::make_shared<flush_data_message>(
		2 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	input.set_sampling_ratio(8);
	input_queue.put(std::make_shared<flush_data_message>(
		3 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(output_queue.size(), 1);
	ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_flush_interval, 3);
	EXPECT_EQ(output->m_metrics->sampling_ratio(), 6);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().sum(), 21);

	// check that if we DECREASE interval while in flight, it works
	input.set_sampling_ratio(6);
	input_queue.put(std::make_shared<flush_data_message>(
		1 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	input.set_sampling_ratio(7);
	input_queue.put(std::make_shared<flush_data_message>(
		2 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	wait_aggr(aggregator, 2);
	aggregator.set_aggregation_interval(2);
	input.set_sampling_ratio(8);
	input_queue.put(std::make_shared<flush_data_message>(
		3 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	input.set_sampling_ratio(9);
	input_queue.put(std::make_shared<flush_data_message>(
		4 * NSECS_PER_SEC,
		&sent_metrics,
		make_unique<draiosproto::metrics>(input),
		1,2,3,4,5));
	for (uint32_t i = 0; output_queue.size() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(output_queue.size(), 1);
	ret = output_queue.get(&output, 0);
	ASSERT_TRUE(ret);
	EXPECT_EQ(output->m_flush_interval, 2);
	EXPECT_EQ(output->m_metrics->sampling_ratio(), 8);
	EXPECT_EQ(output->m_metrics->aggr_sampling_ratio().sum(), 17);

	aggregator.stop();
	pool.stop_all();
}
