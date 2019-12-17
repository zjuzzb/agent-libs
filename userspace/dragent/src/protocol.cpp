#include "protocol.h"
#include "protobuf_compression.h"
#include "common_logger.h"
#include "analyzer_settings.h"

#include <arpa/inet.h>  // htonl

std::shared_ptr<serialized_buffer> dragent_protocol::message_to_buffer(uint64_t ts_ns,
    uint8_t message_type,
    const google::protobuf::MessageLite& message,
    bool v5,
    std::shared_ptr<protobuf_compressor>& compressor)
{
	if (!compressor)
	{
		g_log->error("Cannot compress buffer due to null compressor");
		return nullptr;
	}

	//
	// If the buffer is not big enough, expand it
	//
	if (message.ByteSize() >= MAX_SERIALIZATION_BUF_SIZE_BYTES)
	{
		g_log->error("Message too big. Dropping it.");
		return NULL;
	}

	std::shared_ptr<serialized_buffer> ptr = std::make_shared<serialized_buffer>();
	ptr->ts_ns = ts_ns;
	ptr->message_type = message_type;

	google::protobuf::io::StringOutputStream string_output(&(ptr->buffer));

	//
	// Do the serialization and compression
	//
	compressor->compress(message, string_output);

	return ptr;
}

void dragent_protocol::populate_ids(std::shared_ptr<serialized_buffer>& buf,
                                    uint64_t generation,
                                    uint64_t sequence)
{
	dragent_protocol_header_v5* hdr = (dragent_protocol_header_v5*)buf->buffer.data();
	if (hdr->hdr.version < PROTOCOL_VERSION_NUMBER_10S_FLUSH)
	{
		g_log->error("Error sending message: Attempting to populate IDs for down-rev message");
		return;
	}
	hdr->generation = htonll(generation);
	hdr->sequence = htonll(sequence);
}

uint32_t dragent_protocol::header_len(const dragent_protocol_header_v4 &hdr)
{
	switch (hdr.version)
	{
	case PROTOCOL_VERSION_NUMBER:
		return sizeof(dragent_protocol_header_v4);
	case PROTOCOL_VERSION_NUMBER_10S_FLUSH:
		return sizeof(dragent_protocol_header_v5);
	default:
		return 0;
	}
}


