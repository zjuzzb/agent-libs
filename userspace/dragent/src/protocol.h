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

struct protocol_queue_item
{
	std::string buffer;
	uint64_t ts_ns;
	uint8_t message_type;
};

typedef blocking_queue<std::shared_ptr<protocol_queue_item>> protocol_queue;

namespace dragent_protocol
{
	class protocol_error : public std::runtime_error
	{
	public:
		protocol_error(const std::string& message):
			std::runtime_error(message)
		{ }
	};

	const uint8_t PROTOCOL_VERSION_NUMBER = 4;

	std::shared_ptr<protocol_queue_item> message_to_buffer(
			uint64_t ts_ns,
			uint8_t message_type,
			const google::protobuf::MessageLite& message,
			bool compressed,
			int compression_level = Z_DEFAULT_COMPRESSION);

	/**
	 * @throws protocol_error if the given buffer cannot be converted into
	 *         the given message.
	 */
	template<class T>
	void buffer_to_protobuf(const uint8_t* buf, uint32_t size, T* message);
};

template<class T>
void dragent_protocol::buffer_to_protobuf(const uint8_t* const buf,
                                          const uint32_t size,
                                          T* const message)
{
	google::protobuf::io::ArrayInputStream stream(buf, size);
	google::protobuf::io::GzipInputStream gzstream(&stream);

	if(!message->ParseFromZeroCopyStream(&gzstream))
	{
		g_log->error("Error reading request");
		ASSERT(false);
		throw protocol_error("Failed to parse message to type: " +
		                     message->GetTypeName());
	}
}

template<class T>
void parse_protocol_queue_item(const protocol_queue_item& item, T* message)
{
	const uint8_t* const buf = reinterpret_cast<const uint8_t *>(item.buffer.c_str()) +
		sizeof(dragent_protocol_header);
	size_t size = item.buffer.size() - sizeof(dragent_protocol_header);

	dragent_protocol::buffer_to_protobuf(buf, size, message);
}
