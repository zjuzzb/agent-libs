#pragma once
#include "message_transmitter.h"

namespace test_helpers
{

/**
 * Allows a unit test to inspect the message that was sent to a
 * message transmitter.
 */
template<class TProtoMessage>
class save_last_message_transmitter : public dragent::message_transmitter
{
public:
	void transmit(draiosproto::message_type type, 
	              const google::protobuf::Message& message,
	              protocol_queue::item_priority priority,
	              uint64_t ts_ns) override
	{
		m_type = type;
		m_message = static_cast<const TProtoMessage&>(message);
		m_priority = priority;
		m_ts_ns = ts_ns;
	}

	draiosproto::message_type m_type;
	TProtoMessage m_message;
	protocol_queue::item_priority m_priority;
	uint64_t m_ts_ns;

};

}
