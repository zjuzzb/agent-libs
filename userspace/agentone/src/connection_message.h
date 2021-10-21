#pragma once

#include "protocol.h"

#include <cstdint>
#include <arpa/inet.h>

namespace agentone
{
struct raw_message
{
	dragent_protocol_header_v5 hdr;
	uint8_t* bytes;
	bool buffer_owned;

	raw_message() : bytes(nullptr), buffer_owned(false) {}

	~raw_message()
	{
		if (buffer_owned)
		{
			delete[] bytes;
		}
	}

	raw_message(const raw_message& rhs) : hdr(rhs.hdr), buffer_owned(true)
	{
		bytes = new uint8_t[rhs.payload_length()];
		memcpy(bytes, rhs.bytes, rhs.payload_length());
	}

	uint32_t length() const { return ntohl(hdr.hdr.len); }

	uint32_t payload_length() const { return length() - sizeof(hdr); }
};
}  // namespace agentone
