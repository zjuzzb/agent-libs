#include "sinsp_data_handler.h"

#include "logger.h"

sinsp_data_handler::sinsp_data_handler(dragent_configuration* configuration, protocol_queue* queue):
	m_configuration(configuration),
	m_queue(queue)
{
}

void sinsp_data_handler::sinsp_analyzer_data_ready(uint64_t ts_ns, draiosproto::metrics* metrics)
{
	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		draiosproto::message_type::METRICS, 
		*metrics, 
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	g_log->information("serialization info: ts=" 
		+ NumberFormatter::format(ts_ns / 1000000000) 
		+ ", len=" + NumberFormatter::format(buffer->size()));

	if(!m_queue->put(buffer))
	{
		g_log->error("Queue full, discarding sample");
	}
}
