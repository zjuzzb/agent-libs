#include "sinsp_data_handler.h"
#include "configuration.h"
#include "utils.h"
#include "logger.h"

sinsp_data_handler::sinsp_data_handler(dragent_configuration* configuration,
				       protocol_queue* queue,
				       synchronized_policy_events *policy_events) :
	m_configuration(configuration),
	m_queue(queue),
	m_policy_events(policy_events),
	m_last_loop_ns(0)
{
}

void sinsp_data_handler::sinsp_analyzer_data_ready(uint64_t ts_ns, uint64_t nevts, draiosproto::metrics* metrics, uint32_t sampling_ratio, double analyzer_cpu_pct, double flush_cpu_pct, uint64_t analyzer_flush_duration_ns)
{
	m_last_loop_ns = sinsp_utils::get_current_time_ns();

	if(m_configuration->m_print_protobuf)
	{
		g_log->information(metrics->DebugString());
	}

	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::METRICS,
		*metrics,
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	g_log->information("ts="
		+ NumberFormatter::format(ts_ns / 1000000000)
		+ ", len=" + NumberFormatter::format(buffer->buffer.size())
		+ ", ne=" + NumberFormatter::format(nevts)
 		+ ", c=" + NumberFormatter::format(analyzer_cpu_pct, 2)
		+ ", fp=" + NumberFormatter::format(flush_cpu_pct, 2)
 		+ ", sr=" + NumberFormatter::format(sampling_ratio)
 		+ ", fl=" + NumberFormatter::format(analyzer_flush_duration_ns / 1000000));

	if(!m_queue->put(buffer, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		g_log->information("Queue full, discarding sample");
	}
}

void sinsp_data_handler::security_mgr_policy_events_ready(uint64_t ts_ns, draiosproto::policy_events *events)
{
	if(m_configuration->m_print_protobuf)
	{
		g_log->information(string("Security Events:") + events->DebugString());
	}

	if(!m_policy_events->put(*events))
	{
		g_log->information("Policy events buffer full, discarding");
	}
}

void sinsp_data_handler::security_mgr_throttled_events_ready(uint64_t ts_ns, draiosproto::throttled_policy_events *tevents)
{
	if(m_configuration->m_print_protobuf)
	{
		g_log->information(string("Throttled Security Events:") + tevents->DebugString());
	}

	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::THROTTLED_POLICY_EVENTS,
		*tevents,
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	g_log->information("ts="
			   + NumberFormatter::format(ts_ns / 1000000000)
			   + ", len=" + NumberFormatter::format(buffer->buffer.size())
			   + ", nte=" + NumberFormatter::format(tevents->events_size()));

	if(!m_queue->put(buffer, protocol_queue::BQ_PRIORITY_LOW))
	{
		g_log->information("Queue full, discarding sample");
	}
}
