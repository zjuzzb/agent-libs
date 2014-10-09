#include "sinsp_data_handler.h"
#include "configuration.h"
#include "connection_manager.h"

#include "logger.h"

sinsp_data_handler::sinsp_data_handler(dragent_configuration* configuration, 
		connection_manager* connection_manager, protocol_queue* queue):
	m_configuration(configuration),
	m_connection_manager(connection_manager),
	m_queue(queue)
{
}

void sinsp_data_handler::sinsp_analyzer_data_ready(uint64_t ts_ns, uint64_t nevts, draiosproto::metrics* metrics)
{
	if(!m_connection_manager->is_connected())
	{
		g_log->information("Agent not connected, skipping metric ts=" 
			+ NumberFormatter::format(ts_ns / 1000000000));
		return;
	}

	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		draiosproto::message_type::METRICS, 
		*metrics, 
		m_configuration->m_compression_enabled);

	if(m_configuration->m_print_protobuf)
	{
		g_log->information(metrics->DebugString());
	}

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	g_log->information("ts=" 
		+ NumberFormatter::format(ts_ns / 1000000000) 
		+ ", len=" + NumberFormatter::format(buffer->size()),
		+ ", ne=" + NumberFormatter::format(nevts));

	if(!m_queue->put(buffer, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		g_log->error("Queue full, discarding sample");
	}
}
