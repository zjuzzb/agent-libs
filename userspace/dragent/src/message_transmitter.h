#pragma once
#include "dragent_message_queues.h"
#include <draios.proto.h>

namespace dragent 
{

/** 
 * Pure virtual that can transmit a message (Interface 
 * Segregation Principle). 
 */
class message_transmitter
{
public:
	/**
	 * Send the given message to the backend with the given 
	 * priority. 
	 */
	virtual void transmit(draiosproto::message_type type, 
	                      const google::protobuf::MessageLite& message,
	                      protocol_queue::item_priority priority = protocol_queue::item_priority::BQ_PRIORITY_MEDIUM) = 0;
};

}
