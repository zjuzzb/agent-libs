#include "protocol.h"

#include "logger.h"

SharedPtr<dragent_queue_item> dragent_protocol::message_to_buffer(uint8_t message_type, 
	const google::protobuf::MessageLite& message, bool compressed)
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
	        return NULL;        	
        }

        res = gzip_output.Close();
        if(!res)
        {
	        ASSERT(false);
	        g_log->error("Error serializing buffer (2)");
	        return NULL;	        	
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
	        return NULL;	        	
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
