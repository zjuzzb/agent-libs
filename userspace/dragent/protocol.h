#pragma once

#include "main.h"

#include <google/protobuf/message_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/io/gzip_stream.h>

#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
struct dragent_protocol_header
{
	uint32_t m_sample_len; // length of the whole sample, including this header
	uint8_t m_version; // protocol version
	uint8_t m_messagetype;
} sinsp_sample_header;
#pragma pack(pop)

class dragent_protocol
{
public:
	static const uint8_t PROTOCOL_VERSION_NUMBER = 1;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_METRICS = 1;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_DUMP_REQUEST = 2;
	static const uint8_t PROTOCOL_MESSAGE_TYPE_DUMP_RESPONSE = 3;

	static SharedPtr<dragent_queue_item> message_to_buffer(uint8_t message_type, const google::protobuf::MessageLite& message, bool compressed)
	{
		//
		// Find out how many bytes we need for the serialization
		//
		uint32_t tlen = message.ByteSize();
		
	    //
	    // We allocate 4 additional bytes for the buffer lenght
	    //
	    uint32_t full_len = tlen + sizeof(dragent_protocol_header);
			
	    //
	    // If the buffer is not big enough, expand it
	    //
        if(full_len >= MAX_SERIALIZATION_BUF_SIZE_BYTES)
        {
            g_log->error("Message too big. Dropping it.");
            return NULL;
        }

        SharedPtr<dragent_queue_item> ptr(new dragent_queue_item(full_len));

		//
		// Do the serialization
		//
		if(compressed)
		{
	        google::protobuf::io::ArrayOutputStream array_output(ptr->begin() + sizeof(dragent_protocol_header), tlen);
	        google::protobuf::io::GzipOutputStream gzip_output(&array_output);

	        message.SerializeToZeroCopyStream(&gzip_output);
	        gzip_output.Close();

	        uint32_t compressed_size = (uint32_t)array_output.ByteCount();
	        if(compressed_size > tlen)
	        {
	            ASSERT(false);
	            g_log->error("Unexpected serialization buffer size");
	            return NULL;
	        }

	        ptr->resize(compressed_size + sizeof(dragent_protocol_header));
		}
		else
		{
			google::protobuf::io::ArrayOutputStream array_output(ptr->begin() + sizeof(dragent_protocol_header), tlen);
			message.SerializeToZeroCopyStream(&array_output);
		}

		//
		// Fill the protocol header part
		//
		dragent_protocol_header* hdr = (dragent_protocol_header*) ptr->begin();
		hdr->m_sample_len = htonl(ptr->size());
		hdr->m_version = PROTOCOL_VERSION_NUMBER;
		hdr->m_messagetype = message_type;

        return ptr;
	}
};
