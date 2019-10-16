/**
 * @file
 *
 * Implementation of async_aggregator, which wraps the draiosproto::metrics aggregator
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#define __STDC_FORMAT_MACROS
#include "async_aggregator.h"
#include "analyzer_flush_message.h"
#include "dragent_message_queues.h"
#include "config.h" // needed for sinsp exception
#include "type_config.h"


namespace dragent
{
type_config<uint32_t>::ptr c_samples_between_flush = type_config_builder<uint32_t>(
	10,
	"Number of analyzer samples between each aggregated sample",
	"aggregator",
	"samples_between_flush")
	.hidden()
	.build();

async_aggregator::async_aggregator(flush_queue& input_queue,
                                   flush_queue& output_queue,
                                   uint64_t queue_timeout_ms) :
	dragent::watchdog_runnable("aggregator"),
	m_stop_thread(false),
	m_queue_timeout_ms(queue_timeout_ms),
	m_input_queue(input_queue),
	m_output_queue(output_queue),
	m_builder(),
	m_count_since_flush(0)
{
	m_aggregator = &(m_builder.build_metrics());
	m_aggregated_data = std::make_shared<flush_data_message>(
		0,
		nullptr,
		*(new draiosproto::metrics()),
		0,
		0,
		0,
		0,
		0);
}

async_aggregator::~async_aggregator()
{
	stop();
	delete m_aggregator;
	m_aggregated_data = nullptr;
}

void async_aggregator::do_run()
{
	while(!m_stop_thread && heartbeat())
	{
		std::shared_ptr<flush_data_message> input_data;
		bool ret = m_input_queue.get(&input_data, m_queue_timeout_ms);
		if (!ret)
		{
			continue;
		}

		if(m_stop_thread)
		{
			return;
		}

		(void)heartbeat();

		m_aggregated_data->m_ts = input_data->m_ts;
		m_aggregated_data->m_metrics_sent = input_data->m_metrics_sent;
		m_aggregator->aggregate(*input_data->m_metrics, *m_aggregated_data->m_metrics);

		m_count_since_flush++;
		if (m_count_since_flush == c_samples_between_flush->get_value())
		{
			if (!m_output_queue.put(m_aggregated_data))
			{
				g_logger.format(sinsp_logger::SEV_WARNING, "Queue full, discarding sample");
			}
			m_aggregator->reset();
			m_aggregated_data = std::make_shared<flush_data_message>(
				 0,
				 nullptr,
				 *(new draiosproto::metrics()),
				 0,
				 0,
				 0,
				 0,
				 0);
			m_count_since_flush = 0;
		}
	}
}

void async_aggregator::stop()
{
	m_stop_thread = true;
	m_input_queue.clear();
}

} // end namespace dragent
