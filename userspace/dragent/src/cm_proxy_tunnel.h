#pragma once

#include <memory>
#include <cstdint>

#include <Poco/Net/StreamSocket.h>


class http_tunnel
{
	static const uint32_t default_chunk_size;
public:
	using socket_ptr = std::shared_ptr<Poco::Net::StreamSocket>;
	struct http_response
	{
		bool is_valid;
		uint16_t resp_code;
	};

	http_tunnel() {}

	static socket_ptr establish_tunnel(std::string proxy_host,
	                                   uint16_t proxy_port,
	                                   std::string remote_host,
	                                   uint16_t remote_port);

	static bool is_resp_complete(const Poco::Buffer<char>& buf);
	static http_response parse_resp(const Poco::Buffer<char>& buf);
};
