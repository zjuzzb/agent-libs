#include "protocol.h"
#include "common_logger.h"

std::shared_ptr<protocol_queue_item> dragent_protocol::message_to_buffer(uint64_t ts_ns, uint8_t message_type,
									 const google::protobuf::MessageLite& message, bool compressed,
									 int compression_level)
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

    std::shared_ptr<protocol_queue_item> ptr = std::make_shared<protocol_queue_item>();
    ptr->ts_ns = ts_ns;
    ptr->message_type = message_type;
    ptr->buffer.resize(sizeof(dragent_protocol_header));

    google::protobuf::io::StringOutputStream string_output(&(ptr->buffer));

	//
	// Do the serialization
	//
	if(compressed)
	{
	google::protobuf::io::GzipOutputStream::Options opts;

	opts.compression_level = compression_level;

        google::protobuf::io::GzipOutputStream gzip_output(&string_output, opts);
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
		google::protobuf::io::StringOutputStream string_output(&(ptr->buffer));
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
	dragent_protocol_header* hdr = (dragent_protocol_header*) ptr->buffer.data();
	hdr->len = htonl(ptr->buffer.size());
	hdr->version = PROTOCOL_VERSION_NUMBER;
	hdr->messagetype = message_type;

    return ptr;
}
