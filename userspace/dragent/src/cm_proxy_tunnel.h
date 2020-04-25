#pragma once

#include <memory>
#include <cstdint>
#include <string>

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

	static socket_ptr establish_tunnel(const std::string& proxy_host,
	                                   uint16_t proxy_port,
	                                   const std::string& remote_host,
	                                   uint16_t remote_port);
	static socket_ptr establish_tunnel(const std::string& proxy_host,
	                                   uint16_t proxy_port,
	                                   const std::string& remote_host,
	                                   uint16_t remote_port,
	                                   const std::string& username,
	                                   const std::string& password);

	/**
	 * Determine if we have fully received an HTTP response header.
	 */
	static bool is_resp_complete(const Poco::Buffer<char>& buf);

	/**
	 * Parse an HTTP response according to RFC 2616.
	 */
	static http_response parse_resp(const Poco::Buffer<char>& buf);

	/**
	 * Encodes a username / password combo as described in RFC 7617.
	 *
	 * NOTE: This method assumes the input has already been sanitized.
	 *       Specifically, the username cannot have a ':' character
	 *       in it.
	 *
	 * @return Encoded string
	 */
	static std::string encode_auth(const std::string& user,
	                               const std::string& password);
private:
	static socket_ptr connect(const std::string& proxy_host,
	                          uint16_t proxy_port,
	                          const std::string& http_connect_message);

};
