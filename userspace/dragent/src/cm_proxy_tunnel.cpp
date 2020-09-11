
#include "cm_proxy_tunnel.h"
#include "cm_socket.h"

#include <common_logger.h>
#include <configuration_manager.h>

#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/NumberFormatter.h>
#include <Poco/Buffer.h>
#include <Poco/Base64Encoder.h>

#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <memory>
#include <string>
#include <sstream>
#include <cstdlib> // strtoul
#include <cctype> // isdigit

COMMON_LOGGER();

const uint32_t http_tunnel::default_chunk_size = 1024;

type_config<bool> c_ssl_verify_proxy_certificate(true,
                                                 "Should the agent verify the SSL certificate "
                                                 "sent by the proxy?",
                                                 "http_proxy",
                                                 "ssl_verify_certificate");

type_config<std::string> c_proxy_ca_certificate("root.cert",
                                                "Path to the CA cert for the proxy",
                                                "http_proxy",
                                                "ca_certificate");

cm_socket::ptr http_tunnel::connect(const std::string& proxy_host,
                                    uint16_t proxy_port,
                                    const std::string& http_connect_message)
{
	// Connect to the proxy and send the CONNECT method
	cm_socket::ptr sockptr = std::make_shared<cm_poco_socket>();
	int64_t res;

	if (!sockptr->connect(proxy_host, proxy_port))
	{
		return nullptr;
	}

	uint32_t sent = 0;
	uint32_t to_send = http_connect_message.length();
	while (sent < to_send)
	{
		res = sockptr->send((uint8_t*)(http_connect_message.c_str() + sent),
		                    http_connect_message.length() - sent);
		if (res == 0)
		{
			LOG_ERROR("Connection to proxy unexpectedly terminated");
			return nullptr;
		}
		if (res < 0)
		{
			LOG_ERROR("Error when connecting to proxy: %lld", (long long unsigned)res);
			return nullptr;
		}
		sent += res;
	}

	// Receive the HTTP response
	std::string proxy_resp;
	char buf[default_chunk_size] = {};
	do
	{
		res = sockptr->receive((uint8_t*)buf, sizeof(buf) - 1);
		if (res == 0)
		{
			LOG_ERROR("Connection to proxy unexpectedly terminated during response");
			return nullptr;
		}
		else if (res < 0)
		{
			LOG_ERROR("Error when reading proxy response: %d", (int)res);
			return nullptr;
		}

		proxy_resp.append(buf, res);
	} while (!is_resp_complete(proxy_resp));

	http_response resp = parse_resp(proxy_resp);

	if (!resp.is_valid)
	{
		LOG_ERROR("Received invalid response from proxy server");
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}

	if (resp.resp_code == 407) // Authentication failure
	{
		LOG_ERROR("Proxy server authentication failed (error code %u)", resp.resp_code);
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}
	else if (resp.resp_code != 200)
	{
		LOG_ERROR("Proxy server returned non-success error code %u", resp.resp_code);
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}

	LOG_INFO("Connected through HTTP proxy");

	return sockptr;
}

cm_socket::ptr http_tunnel::openssl_connect(const std::string& proxy_host,
                                            uint16_t proxy_port,
                                            const std::vector<std::string>& ca_cert_paths,
                                            const std::string& ssl_ca_certificate,
                                            const std::string& http_connect_message)
{
	Poco::Net::SocketAddress sa(proxy_host, proxy_port); // Cheat and use poco for DNS lookup
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int res;

	if (sock < 0)
	{
		LOG_ERROR("Error creating socket: %d", sock);
		return nullptr;
	}

	res = ::connect(sock, sa.addr(), sa.length());

	if (res != 0)
	{
		LOG_ERROR("Could not connect to proxy server %s:%uh", proxy_host.c_str(), proxy_port);
		return nullptr;
	}

	// Send the proxy connect message
	uint32_t sent = 0;
	uint32_t to_send = http_connect_message.length();
	while (sent < to_send)
	{
		res = write(sock,
		            http_connect_message.c_str() + sent,
		            http_connect_message.length() - sent);

		if (res == 0)
		{
			LOG_ERROR("Connection to proxy unexpectedly terminated");
			return nullptr;
		}
		if (res < 0)
		{
			LOG_ERROR("Error when connecting to proxy: %d", res);
			return nullptr;
		}
		sent += res;
	}

	// Read the HTTP response from the proxy
	std::string proxy_resp;
	char buf[default_chunk_size] = {};
	do
	{
		res = read(sock, (uint8_t*)buf, sizeof(buf) - 1);
		if (res == 0)
		{
			LOG_ERROR("Connection to proxy unexpectedly terminated during response");
			return nullptr;
		}
		else if (res < 0)
		{
			LOG_ERROR("Error when reading proxy response: %d", (int)res);
			return false;
		}

		proxy_resp.append(buf, res);
	} while (!is_resp_complete(proxy_resp));

	http_response resp = parse_resp(proxy_resp);

	if (!resp.is_valid)
	{
		LOG_ERROR("Received invalid response from proxy server");
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}

	if (resp.resp_code == 407) // Authentication failure
	{
		LOG_ERROR("Proxy server authentication failed (error code %u)", resp.resp_code);
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}
	else if (resp.resp_code != 200)
	{
		LOG_ERROR("Proxy server returned non-success error code %u", resp.resp_code);
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}

	// Once we've fully read the HTTP response, the socket magically becomes a tunnel
	// to the remote endpoint. Wrap the socket in a cm_socket to keep it warm and cozy
	// and send it on its way.
	LOG_INFO("Setting up SSL connection");
	auto oss = std::make_shared<cm_openssl_socket>(ca_cert_paths, ssl_ca_certificate);
	if (oss->connect(sock, proxy_host) && oss->is_valid())
	{
		LOG_INFO("Connected through HTTP proxy");
		return oss;
	}
	return nullptr;
}

cm_socket::ptr http_tunnel::doublessl_connect(const std::string& proxy_host,
                                              uint16_t proxy_port,
                                              const std::vector<std::string>& ca_cert_paths,
                                              const std::string& ssl_ca_certificate,
                                              const std::string& http_connect_message)
{
	//
	// SSL connection 1: Agent <=> Proxy
	//

	BIO* proxy = nullptr;
	SSL_CTX* proxy_ctx = nullptr;
	SSL *proxy_ssl = nullptr;

	proxy_ctx = SSL_CTX_new(SSLv23_client_method());
	if (proxy_ctx == nullptr)
	{
		LOG_ERROR("Unable to build SSL context for proxy connection");
		return nullptr;
	}

	if (c_ssl_verify_proxy_certificate.get_value())
	{
		SSL_CTX_set_verify(proxy_ctx, SSL_VERIFY_PEER, nullptr);
	}
	else
	{
		SSL_CTX_set_verify(proxy_ctx, SSL_VERIFY_NONE, nullptr);
	}

	SSL_CTX_set_verify_depth(proxy_ctx, 9);
	const long flags = SSL_OP_NO_COMPRESSION;
	SSL_CTX_set_options(proxy_ctx, flags);
	SSL_CTX_set_mode(proxy_ctx, SSL_MODE_AUTO_RETRY);

	std::string ca_cert_path(cm_socket::find_ca_cert_path(ca_cert_paths));
	int res = SSL_CTX_load_verify_locations(proxy_ctx,
	                                        c_proxy_ca_certificate.get_value().c_str(),
	                                        ca_cert_path.c_str());

	if (res != 1)
	{
		LOG_ERROR("Couldn't load certificate for proxy: %d", res);
		return nullptr;
	}

	proxy = BIO_new_ssl_connect(proxy_ctx);
	if (proxy == nullptr)
	{
		LOG_ERROR("Couldn't create SSL BIO object for proxy");
		return nullptr;
	}

	std::stringstream ss;
	ss << proxy_host << ":" << proxy_port;
	BIO_set_conn_hostname(proxy, ss.str().c_str());

	BIO_get_ssl(proxy, &proxy_ssl);
	if (proxy_ssl == nullptr)
	{
		LOG_ERROR("Couldn't set up SSL for proxy");
		return nullptr;
	}

	res = SSL_connect(proxy_ssl);
	if (res != 1)
	{
		ERR_print_errors_fp(stderr);
		LOG_ERROR("Establishing SSL connection to proxy failed: %d", res);
		return nullptr;
	}

	// Send the proxy connect message
	res = BIO_puts(proxy, http_connect_message.c_str());
	if (res > 0)
	{
		(void)BIO_flush(proxy);
	}
	else if (res == 0)
	{
		LOG_ERROR("Connection to proxy unexpectedly terminated");
		return nullptr;
	}
	else // (res < 0)
	{
		LOG_ERROR("Error when connecting to proxy: %d", res);
		return nullptr;
	}

	// Read the HTTP response from the proxy
	std::string proxy_resp;
	char buf[default_chunk_size] = {};
	do
	{
		res = BIO_read(proxy, buf, sizeof(buf));
		if (res == 0)
		{
			LOG_ERROR("Connection to proxy unexpectedly terminated during response");
			return nullptr;
		}
		else if (res < 0)
		{
			LOG_ERROR("Error when reading proxy response: %d", (int)res);
			return false;
		}

		proxy_resp.append(buf, res);
	} while (!is_resp_complete(proxy_resp));

	http_response resp = parse_resp(proxy_resp);

	if (!resp.is_valid)
	{
		LOG_ERROR("Received invalid response from proxy server");
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}

	if (resp.resp_code == 407) // Authentication failure
	{
		LOG_ERROR("Proxy server authentication failed (error code %u)", resp.resp_code);
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}
	else if (resp.resp_code != 200)
	{
		LOG_ERROR("Proxy server returned non-success error code %u", resp.resp_code);
		LOG_DEBUG(proxy_resp);
		return nullptr;
	}

	//
	// SSL connection 2: Proxy <=> Collector
	//
	// Once we've fully read the HTTP response, the socket magically becomes a tunnel
	// to the remote endpoint. Now we need to create a second SSL connection to the
	// remote server, which is handled by the openssl_socket.
	LOG_INFO("Setting up SSL connection to collector");
	auto oss = std::make_shared<cm_openssl_socket>(ca_cert_paths, ssl_ca_certificate);
	if (oss->connect(proxy) && oss->is_valid())
	{
		LOG_INFO("Connected through HTTP proxy");
		return oss;
	}
	return nullptr;
}

cm_socket::ptr http_tunnel::establish_tunnel(const proxy_connection conn)
{
	std::string connect_string = build_proxy_connect_string(conn);
	LOG_INFO("Attempting to connect to proxy server %s:%u",
	         conn.proxy_host.c_str(),
	         conn.proxy_port);
	LOG_TRACE(connect_string);

	// SSL connection table
	//  1. ssl_to_proxy: false, ssl_to_collector: false
	//    \_ connect()
	//  2. ssl_to_proxy: true, ssl_to_collector: false
	//    \_ invalid configuration
	//  3. ssl_to_proxy: false, ssl_to_collector: true
	//    \_ openssl_connect()
	//  4. ssl_to_proxy: true, ssl_to_collector: true
	//    \_ doublessl_connect()

	if (conn.ssl_to_proxy)
	{
		if (conn.ssl_to_collector)
		{
			return doublessl_connect(conn.proxy_host,
			                         conn.proxy_port,
			                         conn.ca_cert_paths,
			                         conn.ssl_ca_certificate,
			                         connect_string);
		}
		LOG_ERROR("Invalid configuration: SSL enabled to proxy but not to collector");
		return nullptr;
	}
	else
	{
		if (conn.ssl_to_collector)
		{
			return openssl_connect(conn.proxy_host,
			                       conn.proxy_port,
			                       conn.ca_cert_paths,
			                       conn.ssl_ca_certificate,
			                       connect_string);
		}
	}
	return connect(conn.proxy_host, conn.proxy_port, connect_string);
}

std::string http_tunnel::build_proxy_connect_string(const http_tunnel::proxy_connection& conn)
{
	// Build a connection string that looks like:
	//
	// CONNECT app.sysdigcloud.com:6667 HTTP/1.0
	// Host: app.sysdigcloud.com:6667
	// Content-Length: 0
	// Connection: Keep-Alive
	// Pragma: no-cache
	// Proxy-Authorization: Basic c3lzZGlnOnBhc3N3b3Jk
	std::stringstream connect_stream;
	connect_stream << "CONNECT "
	               << conn.remote_host << ":" << conn.remote_port << " HTTP/1.0\r\n"
	               << "Host: " << conn.remote_host << ":" << conn.remote_port << "\r\n"
	               << "Content-Length: 0\r\n"
	               << "Connection: Keep-Alive\r\n"
	               << "Pragma: no-cache\r\n";
	if (!conn.username.empty())
	{
		std::string auth_str = encode_auth(conn.username, conn.password);
		connect_stream << "Proxy-Authorization: Basic " << auth_str << "\r\n";
	}
	connect_stream << "\r\n";

	return connect_stream.str();
}

bool http_tunnel::is_resp_complete(uint8_t* buf, uint32_t len)
{
	// According to RFC 2616, the response will end with two CRLF sequences
	const char search_str[4] = {'\r', '\n', '\r', '\n'};
	for(uint32_t i = 4; i <= len; ++i)
	{
		if (memcmp(search_str, &buf[i - 4], 4) == 0)
		{
			return true;
		}
	}
	return false;
}

bool http_tunnel::is_resp_complete(std::string buf)
{
	// According to RFC 2616, the response will end with two CRLF sequences
	const char search_str[4] = {'\r', '\n', '\r', '\n'};
	return buf.rfind(search_str, std::string::npos, sizeof(search_str)) != std::string::npos;
}


// I've made an effort to have this parser be RFC 2616 compliant, even though
// all we really care about is the response code.
//
// SP = 0x20 (ASCII space)
// HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
// Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
// After that, it's just headers (which we ignore)
http_tunnel::http_response http_tunnel::parse_resp(const std::string& resp_str)
{
	enum
	{
		VERSION,
		STATUS,
		REASON,
		HEADERS,
		DONE
	} state = VERSION;

	http_response resp {false};
	std::string version;
	std::string code;
	// Response will be an HTTP status line, then some other headers
	// we don't care about, then \r\n\r\n

	for (uint32_t i = 0; i < resp_str.length(); ++i)
	{
		char ch = resp_str[i];
		switch(state)
		{
		case VERSION:
			// The status line starts with the version. We treat it as a
			// freeform string for maximum flexibility / compliance.
			if (ch == ' ')
			{
				state = STATUS;
			}
			else if (ch == '\r' || ch == '\n' || ch == '\0')
			{
				goto parse_error;
			}
			else
			{
				version.append(1, ch);
			}
			break;
		case STATUS:
			// Next is the status code. It should be just a number.
			if (ch == '\r')
			{
				if (i < resp_str.length() - 1 && resp_str[i + 1] != '\n')
				{
					goto parse_error;
				}
				++i;
				// It's valid for a status code to have no descriptive text
				// following (technically, this means the REASON-PHRASE is
				// a null string)
				state = HEADERS;
			}
			else if (ch == ' ')
			{
				state = REASON;
			}
			else if (ch == '\n' || ch == '\0')
			{
				goto parse_error;
			}
			else if (isdigit(ch))
			{
				code.append(1, ch);
			}
			else
			{
				goto parse_error;
			}
			break;
		case REASON:
			// The REASON-PHRASE is a plain-text description of what the
			// status code means. For our purposes we don't care...either
			// it's 200 (SUCCESS) or not 200 and that means the proxy
			// server couldn't connect.
			if (ch == '\r')
			{
				if (i < resp_str.length() - 1 && resp_str[i + 1] != '\n')
				{
					goto parse_error;
				}
				++i;
				state = HEADERS;
			}
			else if (ch == '\n' || ch == '\0')
			{
				goto parse_error;
			}
			break;
		case HEADERS:
			// Yeah, don't care. We don't read any of the headers.
			state = DONE;
			break;
		case DONE:
			// How did we even get here?
			break;
		}

		if (state == DONE)
		{
			break;
		}
	}

	if (code.empty())
	{
		goto parse_error;
	}

	resp.resp_code = strtoul(code.c_str(), NULL, 10);

	if (resp.resp_code == 0)
	{
		goto parse_error;
	}

	resp.is_valid = true;
	return resp;

parse_error:

	resp.is_valid = false;
	return resp;
}

std::string http_tunnel::encode_auth(const std::string& user,
                                     const std::string& password)
{
	std::stringstream ss;

	Poco::Base64Encoder encoder(ss);
	encoder << user << ':' << password;
	encoder.close();

	return ss.str();
}
