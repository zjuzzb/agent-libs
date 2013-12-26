#pragma once

#include "main.h"
#include "protocol.h"

class sinsp_data_handler : public analyzer_callback_interface
{
public:
	sinsp_data_handler(dragent_queue* queue, dragent_configuration* configuration):
		m_queue(queue),
		m_configuration(configuration)
	{
	}

	void sinsp_analyzer_data_ready(uint64_t ts_ns, draiosproto::metrics* metrics)
	{
		SharedPtr<dragent_queue_item> buffer = dragent_protocol::message_to_buffer(dragent_protocol::PROTOCOL_MESSAGE_TYPE_METRICS, *metrics, m_configuration->m_compression_enabled);

		g_log->information("serialization info: ts=%" + NumberFormatter::format(ts_ns / 1000000000) + ", len=%" + NumberFormatter::format(buffer->size()));

		m_queue->put(buffer);
	}

private:
	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
};
