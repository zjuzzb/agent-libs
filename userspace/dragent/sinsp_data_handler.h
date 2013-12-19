#pragma once

#include "main.h"
#include "../libsinsp/proto_header.h"

class sinsp_data_handler : public analyzer_callback_interface
{
public:
	sinsp_data_handler(blocking_queue* queue):
		m_queue(queue)
	{
	}

	void sinsp_analyzer_data_ready(uint64_t ts_ns, char* buffer)
	{
		sinsp_sample_header* hdr = (sinsp_sample_header*)buffer;
		uint32_t size = hdr->m_sample_len;
		uint32_t* pbuflen = &hdr->m_sample_len;

		//
		// Turn the length into network byte order
		//
		*pbuflen = htonl(*pbuflen);

		m_queue->put(new blocking_queue::item(buffer, size));
	}

private:
	blocking_queue* m_queue;
};
