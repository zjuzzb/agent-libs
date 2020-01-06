#include "protobuf_compression.h"

template<class T>
void dragent_protocol::buffer_to_protobuf(const uint8_t* const buf,
                                          const uint32_t size,
                                          T* const message)
{
	google::protobuf::io::ArrayInputStream stream(buf, size);
	google::protobuf::io::GzipInputStream gzstream(&stream);

	if(!message->ParseFromZeroCopyStream(&gzstream))
	{
		g_log->error("Error parsing incoming protobuf");
		ASSERT(false);
		throw protocol_error("Failed to parse message to type: " +
		                     message->GetTypeName());
	}
}


template<class T>
void dragent_protocol::buffer_to_protobuf(const uint8_t* const buf,
                                          const uint32_t size,
                                          T* const message,
                                          protocol_compression_method compression)
{
	google::protobuf::io::ArrayInputStream stream(buf, size);
	google::protobuf::io::GzipInputStream gzstream(&stream);
	bool ret;

	if (compression == protocol_compression_method::GZIP)
	{
		ret = message->ParseFromZeroCopyStream(&gzstream);
	}
	else
	{
		ASSERT(compression == protocol_compression_method::NONE);
		ret = message->ParseFromZeroCopyStream(&stream);
	}

	if(!ret)
	{
		g_log->error("Error parsing incoming protobuf");
		ASSERT(false);
		throw protocol_error("Failed to parse message to type: " +
		                     message->GetTypeName());
	}
}

template<class T>
void parse_protocol_queue_item(const serialized_buffer& item,
                               T* message)
{
	const uint8_t* const buf = reinterpret_cast<const uint8_t *>(item.buffer.c_str());
	size_t size = item.buffer.size();
	dragent_protocol::buffer_to_protobuf(buf, size, message);
}

template<class T>
void parse_protocol_queue_item(const serialized_buffer& item,
                               T* message,
                               protocol_compression_method compression)
{
	const uint8_t* const buf = reinterpret_cast<const uint8_t *>(item.buffer.c_str());
	size_t size = item.buffer.size();
	dragent_protocol::buffer_to_protobuf(buf, size, message, compression);
}
