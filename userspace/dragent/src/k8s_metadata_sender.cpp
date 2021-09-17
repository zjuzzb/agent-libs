#include "k8s_metadata_sender.h"

#include "infrastructure_state.h"

#include <google/protobuf/util/json_util.h>

COMMON_LOGGER();

using namespace google::protobuf::util;

type_config<uint64_t>::ptr c_k8s_metadata_interval =
    type_config_builder<uint64_t>(300,
                                  "Interval in which to send K8s metadata",
                                  "k8s_metadata",
                                  "interval")
        .build();

k8s_metadata_sender* k8s_metadata_sender::s_k8s_metadata_sender = new k8s_metadata_sender();

k8s_metadata_sender& k8s_metadata_sender::instance()
{
	return *k8s_metadata_sender::s_k8s_metadata_sender;
}

k8s_metadata_sender::k8s_metadata_sender()
    : feature_base(K8S_METADATA,
                   &draiosproto::feature_status::set_k8s_metadata_enabled,
                   {COINTERFACE}),
      m_analyzer(nullptr),
      m_protocol_handler(nullptr),
      m_interval(nullptr)
{
}

void k8s_metadata_sender::init(sinsp_analyzer* analyzer, protocol_handler* protocol_handler)
{
	m_interval =
	    make_unique<run_on_interval>(c_k8s_metadata_interval->get_value() * ONE_SECOND_IN_NS);

	set_analyzer(analyzer);
	set_protocol_handler(protocol_handler);
};

void k8s_metadata_sender::send_k8s_metadata_message(uint64_t now)
{
	infrastructure_state* infra_state = nullptr;

	if (!get_enabled())
	{
		return;
	}

	if (m_analyzer == nullptr || m_protocol_handler == nullptr)
	{
		LOG_ERROR("analyzer or protocol handler is NULL, not sending k8s metadata");
		return;
	}

	infra_state = m_analyzer->mutable_infra_state();
	if (infra_state == nullptr)
	{
		LOG_ERROR("infrastructure_state is NULL, not sending k8s metadata");
		return;
	}

	if (!m_analyzer->check_k8s_delegation())
	{
		LOG_INFO("Agent is not delegated, not sending k8s metadata");
		return;
	}

	auto msg = infra_state->make_metadata_message(now);

	if (msg == nullptr)
	{
		LOG_WARNING("Failed to create metadata message");
	}
	else
	{
		LOG_DEBUG("Sending metadata message");
		if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_TRACE))
		{
			std::string json;
			MessageToJsonString(*msg, &json);
			LOG_TRACE("%s", json.c_str());
		}
		m_protocol_handler->transmit(draiosproto::message_type::K8S_METADATA,
		                             *msg,
		                             protocol_queue::item_priority::BQ_PRIORITY_LOW,
		                             msg->timestamp_ns());
	}
}

void k8s_metadata_sender::send_k8s_metadata_message_on_interval(uint64_t now)
{
	if (!get_enabled())
	{
		return;
	}

	if (m_interval == nullptr)
	{
		LOG_INFO("interval is NULL, not sending k8s metadata");
		return;
	}

	m_interval->run([this, now]() { send_k8s_metadata_message(now); }, now);
}

