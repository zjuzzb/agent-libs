#pragma once

#include <memory>

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

typedef struct {
	string buffer;
	uint64_t ts_ns;
	uint8_t message_type;
} protocol_queue_item;

typedef blocking_queue<std::shared_ptr<protocol_queue_item>> protocol_queue;

class dragent_protocol
{
public:
	static const uint8_t PROTOCOL_VERSION_NUMBER = 4;

	static std::shared_ptr<protocol_queue_item> message_to_buffer(uint64_t ts_ns, uint8_t message_type,
								      const google::protobuf::MessageLite& message, bool compressed,
								      int compression_level = Z_DEFAULT_COMPRESSION);

	template<class T>
	static bool buffer_to_protobuf(const uint8_t* buf, uint32_t size, T* message);
};

template<class T>
bool dragent_protocol::buffer_to_protobuf(const uint8_t* buf, uint32_t size, T* message)
{
	google::protobuf::io::ArrayInputStream stream(buf, size);
	google::protobuf::io::GzipInputStream gzstream(&stream);

	bool res = message->ParseFromZeroCopyStream(&gzstream);
	if(!res)
	{
		g_log->error("Error reading request");
		ASSERT(false);
		return false;
	}

	return true;
}
