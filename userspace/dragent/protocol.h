#pragma once

#include "main.h"
#include "blocking_queue.h"

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
	uint32_t len; // length of the whole sample, including this header
	uint8_t version; // protocol version
	uint8_t messagetype;
};
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

        SharedPtr<dragent_queue_item> ptr(new dragent_queue_item());
        ptr->resize(sizeof(dragent_protocol_header));

        google::protobuf::io::StringOutputStream string_output(ptr);

		//
		// Do the serialization
		//
		if(compressed)
		{
	        google::protobuf::io::GzipOutputStream gzip_output(&string_output);
	        bool res = message.SerializeToZeroCopyStream(&gzip_output);
	        if(!res)
	        {
		        ASSERT(false);
		        g_log->error("Error serializing buffer (1)");	        	
	        }

	        res = gzip_output.Close();
	        if(!res)
	        {
		        ASSERT(false);
		        g_log->error("Error serializing buffer (2)");	        	
	        }
		}
		else
		{
			google::protobuf::io::StringOutputStream string_output(ptr);
			bool res = message.SerializeToZeroCopyStream(&string_output);
	        if(!res)
	        {
		        ASSERT(false);
		        g_log->error("Error serializing buffer (3)");	        	
	        }
		}

		//
		// Fill the protocol header part
		//
		dragent_protocol_header* hdr = (dragent_protocol_header*) ptr->data();
		hdr->len = htonl(ptr->size());
		hdr->version = PROTOCOL_VERSION_NUMBER;
		hdr->messagetype = message_type;

        return ptr;
	}
};
