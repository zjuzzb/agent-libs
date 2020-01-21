#include <gtest.h>
#include "configuration.h"
#include "sinsp_factory.h"
#include "sinsp_worker.h"
#include "sinsp_mock.h"
#include "watchdog_runnable_pool.h"
#include "protocol_handler.h"
#include "protobuf_compression.h"
#include "protocol.h"

using namespace dragent;
using namespace test_helpers;

namespace {

/**
 * Run the sinsp worker thread with the given config and the
 * given inspector.
 */
void run_sinsp_worker(const sinsp::ptr& inspector,
		      dragent_configuration& config,
		      protocol_queue& queue,
		      protocol_handler& handler)
{
	sinsp_factory::inject(inspector);

	dragent_configuration::m_terminate = false;
	internal_metrics::sptr_t im = std::make_shared<internal_metrics>();

	capture_job_handler job_handler(&config, &queue);
	sinsp_worker worker(&config, im, handler, &job_handler);
	worker.run();
}

/**
 * Run the sinsp worker thread with the given inspector. This
 * will load a config with defaults
 */
void run_sinsp_worker(const sinsp::ptr &inspector,
		      protocol_queue& queue,
		      protocol_handler& handler)
{
	dragent_configuration config;
	config.init();
	run_sinsp_worker(inspector, config, queue, handler);
}

}

TEST(sinsp_worker_test, DISABLED_end_to_end_basic)
{
	std::shared_ptr<sinsp_mock> inspector = std::make_shared<sinsp_mock>();

	// Make some fake events
	uint64_t ts = 1095379199000000000ULL;
	auto &tinfo55 = inspector->build_thread().tid(55).commit();
	auto &tinfo75 = inspector->build_thread().tid(75).commit();
	inspector->build_event(tinfo55).ts(ts).count(5).commit();
	inspector->build_event(tinfo55).ts(ts).count(1000).commit();
	inspector->build_event(tinfo75).count(1).commit();

	// Run the sinsp_worker
	protocol_queue queue(MAX_SAMPLE_STORE_SIZE);
	protocol_handler handler(queue);
	run_sinsp_worker(inspector, queue, handler);

	// Inspect the protocol queue
	ASSERT_EQ(1, queue.size());
	std::shared_ptr<serialized_buffer> item;
	queue.get(&item, 300 /*timeout_ms*/);
	ASSERT_EQ(draiosproto::message_type::METRICS, item->message_type);

	draiosproto::metrics metrics;
	parse_protocol_queue_item(*item, &metrics);

	ASSERT_EQ(1, metrics.programs_size());
	ASSERT_EQ(2, metrics.programs(0).pids_size());
	ASSERT_EQ(55, metrics.programs(0).pids(0));
	ASSERT_EQ(75, metrics.programs(0).pids(1));

}

TEST(sinsp_worker_test, is_stall_fatal_in_capture_mode)
{
	dragent_configuration config;
	config.m_input_filename = "capture_file.scap";
	protocol_queue queue(MAX_SAMPLE_STORE_SIZE);
	protocol_handler handler(queue);
	sinsp_worker worker(&config, nullptr, handler,  nullptr);
	ASSERT_FALSE(worker.is_stall_fatal());
}

TEST(sinsp_worker_test, is_stall_fatal_in_driver_mode)
{
	dragent_configuration config;
	protocol_queue queue(MAX_SAMPLE_STORE_SIZE);
	protocol_handler handler(queue);
	sinsp_worker worker(&config, nullptr, handler,  nullptr);
	ASSERT_TRUE(worker.is_stall_fatal());
}
