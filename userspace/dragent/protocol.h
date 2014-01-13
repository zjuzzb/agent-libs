#pragma once

#include <google/protobuf/message_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/io/gzip_stream.h>

#include "main.h"
#include "blocking_queue.h"

#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
struct dragent_protocol_header
{
	uint32_t len; // length of the whole sample, including this header
	uint8_t version; // protocol version
	uint8_t messagetype;
};
#pragma pack(pop)

typedef string protocol_queue_item;
typedef blocking_queue<SharedPtr<protocol_queue_item>> protocol_queue;

class dragent_protocol
{
public:
	static const uint8_t PROTOCOL_VERSION_NUMBER = 1;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_METRICS = 1;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_DUMP_REQUEST = 2;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_DUMP_RESPONSE = 3;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_EXEC_COMMAND_REQUEST = 4;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_EXEC_COMMAND_RESPONSE = 5;

	static SharedPtr<protocol_queue_item> message_to_buffer(uint8_t message_type, 
		const google::protobuf::MessageLite& message, bool compressed);
};
