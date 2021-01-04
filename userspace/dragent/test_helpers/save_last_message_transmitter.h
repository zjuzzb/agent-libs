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
	              const google::protobuf::MessageLite& message,
	              protocol_queue::item_priority priority) override
	{
		m_type = type;
		m_message = static_cast<const TProtoMessage&>(message);
		m_priority = priority;
	}

	draiosproto::message_type m_type;
	TProtoMessage m_message;
	protocol_queue::item_priority m_priority;


};

}
