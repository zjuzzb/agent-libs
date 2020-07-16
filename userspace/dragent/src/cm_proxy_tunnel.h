#pragma once

#include "cm_socket.h"

#include <openssl/ssl.h>

#include <memory>
#include <cstdint>
#include <string>

#include <Poco/Net/StreamSocket.h>

/**
 * Class to help with establishing a tunnel through an HTTP proxy.
 *
 * This class defines a set of helper methods. The entry point of this
 * class is the static function establish_tunnel.
 */
class http_tunnel
{
	/**
	 * Buffer size for a single read when connecting to the proxy.
	 */
	static const uint32_t default_chunk_size;
public:
	struct http_response
	{
		bool is_valid;
		uint16_t resp_code;
	};

	struct proxy_connection
	{
		std::string proxy_host;
		uint16_t proxy_port;
		std::string remote_host;
		uint16_t remote_port;
		std::string username;
		std::string password;
		bool ssl;
		std::vector<std::string> ca_cert_paths;
		std::string ssl_ca_certificate;
	};

	http_tunnel() {}

	/**
	 * Establish a TCP tunnel through an HTTP proxy.
	 *
	 * @return A pointer to a cm_socket for the tunnel, or nullptr on error.
	 */
	static cm_socket::ptr establish_tunnel(const proxy_connection conn);

	/**
	 * Determine if we have fully received an HTTP response header.
	 */
	static bool is_resp_complete(uint8_t* buf, uint32_t len);
	static bool is_resp_complete(std::string buf);

	/**
	 * Parse an HTTP response according to RFC 2616.
	 */
	static http_response parse_resp(const std::string& resp_str);

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

	/**
	 * Builds an HTTP CONNECT string
	 */
	static std::string build_proxy_connect_string(const proxy_connection& conn);

	static cm_socket::ptr connect(const std::string& proxy_host,
	                              uint16_t proxy_port,
	                              const std::string& http_connect_message);

	static cm_socket::ptr openssl_connect(const std::string& proxy_host,
	                                      uint16_t proxy_port,
	                                      const std::vector<std::string>& ca_cert_paths,
	                                      const std::string& ssl_ca_certificate,
	                                      const std::string& http_connect_message);

};
