#include "protocol.h"
#include "common_logger.h"
#include "analyzer_settings.h"

#include <arpa/inet.h>  // htonl

std::shared_ptr<serialized_buffer> dragent_protocol::message_to_buffer(
    uint64_t ts_ns,
    uint8_t message_type,
    const google::protobuf::MessageLite& message,
    bool v5,
    bool compressed,
    int compression_level)
{
	//
	// Find out how many bytes we need for the serialization
	//
	uint32_t tlen = message.ByteSize();

	uint32_t header_size =
	    v5 ? sizeof(dragent_protocol_header_v5) : sizeof(dragent_protocol_header_v4);
	uint32_t full_len = tlen + header_size;

	//
	// If the buffer is not big enough, expand it
	//
	if (full_len >= MAX_SERIALIZATION_BUF_SIZE_BYTES)
	{
		g_log->error("Message too big. Dropping it.");
		return NULL;
	}

	std::shared_ptr<serialized_buffer> ptr = std::make_shared<serialized_buffer>();
	ptr->ts_ns = ts_ns;
	ptr->message_type = message_type;

	// the resize will create a string of the length of the header. then the output
	// stream will be smart enough to start inserting after it
	ptr->buffer.resize(header_size);
	google::protobuf::io::StringOutputStream string_output(&(ptr->buffer));

	//
	// Do the serialization
	//
	if (compressed)
	{
		google::protobuf::io::GzipOutputStream::Options opts;

		opts.compression_level = compression_level;

		google::protobuf::io::GzipOutputStream gzip_output(&string_output, opts);
		bool res = message.SerializeToZeroCopyStream(&gzip_output);
		if (!res)
		{
			ASSERT(false);
			g_log->error("Error serializing buffer (1)");
			return NULL;
		}

		res = gzip_output.Close();
		if (!res)
		{
			ASSERT(false);
			g_log->error("Error serializing buffer (2)");
			return NULL;
		}
	}
	else
	{
		google::protobuf::io::StringOutputStream string_output(&(ptr->buffer));
		bool res = message.SerializeToZeroCopyStream(&string_output);
		if (!res)
		{
			ASSERT(false);
			g_log->error("Error serializing buffer (3)");
			return NULL;
		}
	}

	//
	// Fill the protocol header part
	//
	dragent_protocol_header_v4* hdr;
	if (!v5)
	{
		hdr = (dragent_protocol_header_v4*)ptr->buffer.data();
		hdr->version = PROTOCOL_VERSION_NUMBER;
	}
	else
	{
		dragent_protocol_header_v5* ext_hdr = (dragent_protocol_header_v5*)ptr->buffer.data();
		hdr = &ext_hdr->hdr;
		hdr->version = PROTOCOL_VERSION_NUMBER_10S_FLUSH;
	}

	hdr->len = htonl(ptr->buffer.size());
	hdr->messagetype = message_type;

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
