#pragma once

#include <memory>

#include <google/protobuf/message_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/io/gzip_stream.h>

#include <string>

#include <common_logger.h>

#include "common_assert.h"

class protobuf_compressor;

enum class protocol_compression_method
{
	NONE,
	GZIP
};

struct serialized_buffer
{
	std::string buffer;
	uint64_t ts_ns;
	uint8_t message_type;
	uint32_t flush_interval; // special value only used for metrics messages. ugly.
};

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define ntohll(x) ((((uint64_t)ntohl(x)) << 32) + ntohl((x) >> 32))

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

using protocol_version = uint8_t;

const protocol_version PROTOCOL_VERSION_NUMBER = 4;
const protocol_version PROTOCOL_VERSION_NUMBER_10S_FLUSH = 5;

bool version_is_valid(protocol_version ver);

std::shared_ptr<serialized_buffer> message_to_buffer(uint64_t ts_ns,
        uint8_t message_type,
        const google::protobuf::MessageLite& message,
        std::shared_ptr<protobuf_compressor>& compressor);

/**
 * @throws protocol_error if the given buffer cannot be converted into
 *         the given message.
 *
 * NOTE: Legacy behavior is that EVERY incoming protobuf is gzip-
 *       compressed. When operating in legacy mode, we will continue
 *       to assume gzip compression.
 */
template<class T>
void buffer_to_protobuf(const uint8_t* buf, uint32_t size, T* message);

/**
 * @throws protocol_error if the given buffer cannot be converted into
 *         the given message.
 */
template<class T>
void buffer_to_protobuf(const uint8_t* buf,
                        uint32_t size,
                        T* message,
                        protocol_compression_method compression);

void populate_ids(std::shared_ptr<serialized_buffer>& buf,
                  uint64_t generation,
                  uint64_t sequence);

/**
 * Extract the generation and sequence number from a serialized buffer.
 *
 * @param[in]   buf         The serialized buffer
 * @param[out]  generation  The generation number from the buffer
 * @param[out]  sequence    The sequence number from the buffer
 *
 * @return true if the out parameters are valid; false otherwise
 */
bool get_ids(std::shared_ptr<serialized_buffer>& buf,
             uint64_t& generation,
             uint64_t& sequence);

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
uint32_t header_len(protocol_version version);


/**
 * Parse the v4 header from a byte buffer.
 */
bool parse_header(const uint8_t* buf, uint32_t buf_len, dragent_protocol_header_v4* hdr_out);
/**
 * Parse the v5 header from a byte buffer.
 */
bool parse_header(const uint8_t* buf, uint32_t buf_len, dragent_protocol_header_v5* hdr_out);

}

#include "protocol.hpp"
