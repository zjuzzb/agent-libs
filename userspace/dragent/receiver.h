#pragma once

#include <google/protobuf/io/gzip_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include "draios.pb.h"
#include "dumper_worker.h"
#include "protocol.h"

class dragent_receiver : public Runnable
{
public:
	dragent_receiver(dragent_queue* queue, dragent_configuration* configuration, connection_manager* connection_manager);
	
	void run();

private:
	void handle_dump_request(uint8_t* buf, uint32_t size);

	static const uint32_t RECEIVER_BUFSIZE = 32 * 1024;
	static const string m_name;

	Buffer<uint8_t> m_buffer;
	dragent_queue* m_queue;
	dragent_configuration* m_configuration;
	connection_manager* m_connection_manager;
};
