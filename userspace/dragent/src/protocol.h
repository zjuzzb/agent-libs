#pragma once

#include <memory>

#include <google/protobuf/message_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/io/gzip_stream.h>

#include <string>

#include <common_logger.h>

#include "common_assert.h"

struct serialized_buffer
{
	std::string buffer;
	uint64_t ts_ns;
	uint8_t message_type;
	uint32_t flush_interval; // special value only used for metrics messages. ugly.
};

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))

#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
struct dragent_protocol_header_v4
{
	uint32_t len; // length of the whole sample, including this header
	uint8_t version; // protocol version
	uint8_t messagetype;
};
struct dragent_protocol_header_v5
{
	dragent_protocol_header_v4 hdr; // must be first
	uint64_t generation;
	uint64_t sequence;
};
#pragma pack(pop)

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
const uint8_t PROTOCOL_VERSION_NUMBER_10S_FLUSH = 5;

std::shared_ptr<serialized_buffer> message_to_buffer(uint64_t ts_ns,
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

void populate_ids(std::shared_ptr<serialized_buffer>& buf,
				  uint64_t generation,
				  uint64_t sequence);

/**
 * Returns the full length of the header for a given message.
 *
 * Although this function takes a v4 header, it will check the message
 * version and return the header length that is correct for the version
 * described by the header.
 *
 * @return The header length, or 0 if header is not valid
 */
uint32_t header_len(const dragent_protocol_header_v4& hdr);

}

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
void parse_protocol_queue_item(const serialized_buffer& item, T* message)
{
	const uint8_t* const buf = reinterpret_cast<const uint8_t *>(item.buffer.c_str());
	size_t size = item.buffer.size();
	dragent_protocol::buffer_to_protobuf(buf, size, message);
}
