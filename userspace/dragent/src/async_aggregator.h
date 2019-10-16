/**
 * @file
 *
 * Interface to async aggregator
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "aggregator_overrides.h"
#include "analyzer_flush_message.h"
#include "blocking_queue.h"
#include "watchdog_runnable.h"

namespace dragent
{

/**
 * The async stage which takes queue items, runs them through the aggregator
 * and eventually puts them on an output queue.
 */
class async_aggregator : public dragent::watchdog_runnable
{
public:
	/**
	 * Initialize this async_aggregator.
	 */
	async_aggregator(blocking_queue<std::shared_ptr<flush_data_message>>& input_queue,
					 blocking_queue<std::shared_ptr<flush_data_message>>& output_queue,
					 uint64_t queue_timeout_ms = 300);

	~async_aggregator();

	void stop();

private:
	/**
	 * This will block waiting for work, do that work, then block
	 * again waiting for work. This method will terminate when the
	 * async_aggregator is destroyed or stop() is called.
	 */
	void do_run();

	std::atomic<bool> m_stop_thread;
	uint64_t m_queue_timeout_ms;

	blocking_queue<std::shared_ptr<flush_data_message>>& m_input_queue;
	blocking_queue<std::shared_ptr<flush_data_message>>& m_output_queue;
	message_aggregator_builder_impl m_builder;
	agent_message_aggregator<draiosproto::metrics>* m_aggregator;
	std::shared_ptr<flush_data_message> m_aggregated_data;

	uint32_t m_count_since_flush;
};

} // end namespace dragent
