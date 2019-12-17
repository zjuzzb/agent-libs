#include <memory>

#include "protocol_handler.h"
#include "configuration.h"
#include "utils.h"
#include "common_logger.h"

#include "draios.pb.h"
#include "tap.pb.h"
#include "secure.pb.h"

COMMON_LOGGER();

type_config<bool> protocol_handler::c_print_protobuf(
	false,
	"set to true to print the protobuf with each flush",
	"protobuf_print");

type_config<bool> protocol_handler::c_compression_enabled(
	true,
	"set to true to compress protobufs sent to the collector",
	"compression",
	"enabled");

type_config<bool> protocol_handler::c_audit_tap_debug_only(
	true,
	"set to true to only log audit tap, but not emit",
	"audit_tap",
	"debug_only");

type_config<bool> protocol_handler::c_secure_audit_debug_enabled(
	false,
	"set to true to log secure audit protobufs",
	"secure_audit",
	"debug");

protocol_handler::protocol_handler(protocol_queue& queue) :
    m_last_loop_ns(0),
    m_queue(queue)
{
}

protocol_handler::~protocol_handler()
{
}

std::shared_ptr<serialized_buffer> protocol_handler::handle_uncompressed_sample(uint64_t ts_ns,
                          std::shared_ptr<draiosproto::metrics>& metrics,
						  uint32_t flush_interval)
{
	ASSERT(metrics);
	m_last_loop_ns = sinsp_utils::get_current_time_ns();

	if(c_print_protobuf.get_value())
	{
		LOG_INFO(metrics->DebugString());
	}

	std::shared_ptr<serialized_buffer> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::METRICS,
		*metrics,
		c_compression_enabled.get_value());

	buffer->flush_interval = flush_interval;

	if(!buffer)
	{
		LOG_ERROR("NULL converting message to buffer");
		return nullptr;
	}

	return buffer;
}

uint64_t protocol_handler::get_last_loop_ns() const
{
	return m_last_loop_ns;
}

void protocol_handler::security_mgr_policy_events_ready(uint64_t ts_ns, draiosproto::policy_events *events)
{
	if(c_print_protobuf.get_value())
	{
		LOG_INFO(std::string("Security Events:") + events->DebugString());
	}

	std::shared_ptr<serialized_buffer> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::POLICY_EVENTS,
		*events,
		c_compression_enabled.get_value());

	if(!buffer)
	{
		LOG_ERROR("NULL converting message to buffer");
		return;
	}

	LOG_INFO("sec_evts len=" + NumberFormatter::format(buffer->buffer.size())
			   + ", ne=" + NumberFormatter::format(events->events_size()));

	if(!m_queue.put(buffer, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		LOG_INFO("Queue full, discarding sample");
	}
}

void protocol_handler::security_mgr_throttled_events_ready(uint64_t ts_ns,
							     draiosproto::throttled_policy_events *tevents,
							     uint32_t total_throttled_count)
{
	if(c_print_protobuf.get_value())
	{
		LOG_INFO(std::string("Throttled Security Events:") + tevents->DebugString());
	}

	std::shared_ptr<serialized_buffer> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::THROTTLED_POLICY_EVENTS,
		*tevents,
		c_compression_enabled.get_value());

	if(!buffer)
	{
		LOG_ERROR("NULL converting message to buffer");
		return;
	}

	LOG_INFO("sec_evts len=" + NumberFormatter::format(buffer->buffer.size())
			   + ", nte=" + NumberFormatter::format(tevents->events_size())
			   + ", tcount=" + NumberFormatter::format(total_throttled_count));

	if(!m_queue.put(buffer, protocol_queue::BQ_PRIORITY_LOW))
	{
		LOG_INFO("Queue full, discarding sample");
	}
}

void protocol_handler::security_mgr_comp_results_ready(uint64_t ts_ns, const draiosproto::comp_results *results)
{
	if(c_print_protobuf.get_value())
	{
		LOG_INFO(std::string("Compliance Results:") + results->DebugString());
	}

	std::shared_ptr<serialized_buffer> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::COMP_RESULTS,
		*results,
		c_compression_enabled.get_value());

	if(!buffer)
	{
		LOG_ERROR("NULL converting message to buffer");
		return;
	}

	LOG_INFO("sec_comp_results len=" + NumberFormatter::format(buffer->buffer.size())
			   + ", ne=" + NumberFormatter::format(results->results_size()));

	if(!m_queue.put(buffer, protocol_queue::BQ_PRIORITY_LOW))
	{
		LOG_INFO("Queue full, discarding sample");
	}
}

void protocol_handler::audit_tap_data_ready(uint64_t ts_ns, const tap::AuditLog *audit_log)
{
	if(c_print_protobuf.get_value() || c_audit_tap_debug_only.get_value())
	{
		LOG_INFO(std::string("Audit tap data:") + audit_log->DebugString());
	}

	std::shared_ptr<serialized_buffer> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::AUDIT_TAP,
		*audit_log,
		true /* compression always enabled */);

	if(!buffer)
	{
		LOG_ERROR("NULL converting audit_tap message to buffer");
		return;
	}

	LOG_INFO("audit_tap len=" + NumberFormatter::format(buffer->buffer.size())
			   + ", np=" + NumberFormatter::format(audit_log->newprocessevents().size())
		           + ", pe=" + NumberFormatter::format(audit_log->processexitevents().size())
		           + ", c=" + NumberFormatter::format(audit_log->connectionevents().size())
			   + ", e=" + NumberFormatter::format(audit_log->environmentvariables().size())
			   );

	if(c_audit_tap_debug_only.get_value())
	{
		return;
	}

	if(!m_queue.put(buffer, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		LOG_INFO("Queue full, discarding sample");
	}
}

std::shared_ptr<serialized_buffer> protocol_handler::handle_log_report(uint64_t ts_ns,
					 const draiosproto::dirty_shutdown_report& report)
{
	std::shared_ptr<serialized_buffer> report_serialized = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::DIRTY_SHUTDOWN_REPORT,
		report,
		c_compression_enabled.get_value());

	if(!report_serialized)
	{
		g_log->error("NULL converting message to buffer");
		return nullptr;
	}
	return report_serialized;
}

void protocol_handler::secure_audit_data_ready(uint64_t ts_ns, const secure::Audit *secure_audit)
{
	if(c_secure_audit_debug_enabled.get_value())
	{
		LOG_INFO(std::string("Secure Audit data:") + secure_audit->DebugString());
	}

	std::shared_ptr<serialized_buffer> buffer = dragent_protocol::message_to_buffer(
		ts_ns,
		draiosproto::message_type::SECURE_AUDIT,
		*secure_audit,
		true /* compression always enabled */);

	if(!buffer)
	{
		LOG_ERROR("NULL converting secure_audit message to buffer");
		return;
	}

	LOG_INFO("secure_audit len=" + NumberFormatter::format(buffer->buffer.size())
			   + ", conn=" + NumberFormatter::format(secure_audit->connections().size())
			   + ", cmd=" + NumberFormatter::format(secure_audit->executed_commands().size())
			   + ", ke=" + NumberFormatter::format(secure_audit->k8s_audits().size())
			   );

	if(!m_queue.put(buffer, protocol_queue::BQ_PRIORITY_MEDIUM))
	{
		LOG_INFO("Queue full, discarding sample");
	}
}
