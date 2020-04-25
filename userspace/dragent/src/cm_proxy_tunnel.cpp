
#include "cm_proxy_tunnel.h"

#include <common_logger.h>

#include <Poco/Net/StreamSocket.h>
#include <Poco/NumberFormatter.h>
#include <Poco/Buffer.h>
#include <Poco/Base64Encoder.h>

#include <cstdint>
#include <memory>
#include <string>
#include <sstream>
#include <cstdlib> // strtoul
#include <cctype> // isdigit

COMMON_LOGGER();

const uint32_t http_tunnel::default_chunk_size = 1024;


http_tunnel::socket_ptr http_tunnel::connect(const std::string& proxy_host,
                                             uint16_t proxy_port,
                                             const std::string& http_connect_message)
{
	// Connect to the proxy and send the CONNECT method
	Poco::Net::SocketAddress sa(proxy_host, proxy_port);
	socket_ptr ssp = std::make_shared<Poco::Net::StreamSocket>();
	ssp->connect(sa);
	ssp->sendBytes(http_connect_message.c_str(), http_connect_message.length());

	// Receive the HTTP response.
	// We don't actually need all of it, just the status line.
	Poco::Buffer<char> buf(0);
	Poco::FIFOBuffer read_buf(default_chunk_size);
	int res = ssp->receiveBytes(read_buf);

	if (res <= 0)
	{
		return nullptr;
	}
	read_buf.read(buf);
	buf.append('\0');

	http_response resp = parse_resp(buf);

	if (!resp.is_valid)
	{
		LOG_ERROR("Received invalid response from proxy server");
		return nullptr;
	}

	if (resp.resp_code == 407) // Authentication failure
	{
		LOG_ERROR("Proxy server authentication failed (error code %u)", resp.resp_code);
		return nullptr;
	}
	else if (resp.resp_code != 200)
	{
		LOG_ERROR("Proxy server returned non-success error code %u", resp.resp_code);
		return nullptr;
	}

	LOG_INFO("Connected through HTTP proxy");

	return ssp;
}

http_tunnel::socket_ptr http_tunnel::establish_tunnel(const std::string& proxy_host,
                                                      uint16_t proxy_port,
                                                      const std::string& remote_host,
                                                      uint16_t remote_port)
{
	// Build a connection string that looks like:
	//
	// CONNECT app.sysdigcloud.com:6667 HTTP/1.0
	// Host: app.sysdigcloud.com:6667
	// Content-Length: 0
	// Connection: Keep-Alive
	// Pragma: no-cache
	std::string port_str = Poco::NumberFormatter::format(remote_port);
	std::stringstream connect_stream;
	connect_stream << "CONNECT " <<
	                  remote_host << ":" << port_str <<
	                  " HTTP/1.0\r\n" <<
	                  "Host: " << remote_host << ":" << port_str << "\r\n" <<
	                  "Content-Length: 0\r\n" <<
	                  "Connection: Keep-Alive\r\n" <<
	                  "Pragma: no-cache\r\n\r\n";
	std::string connect_string = connect_stream.str();

	LOG_INFO("Attempting to connect to proxy server %s:%u", proxy_host.c_str(), proxy_port);
	LOG_TRACE(connect_string);

	return connect(proxy_host, proxy_port, connect_string);
}

http_tunnel::socket_ptr http_tunnel::establish_tunnel(const std::string& proxy_host,
                                                      uint16_t proxy_port,
                                                      const std::string& remote_host,
                                                      uint16_t remote_port,
                                                      const std::string& username,
                                                      const std::string& password)
{
	// Build a connection string that looks like:
	//
	// CONNECT app.sysdigcloud.com:6667 HTTP/1.0
	// Host: app.sysdigcloud.com:6667
	// Proxy-Authorization: Basic c3lzZGlnOnBhc3N3b3Jk
	// Content-Length: 0
	// Connection: Keep-Alive
	// Pragma: no-cache
	std::string port_str = Poco::NumberFormatter::format(remote_port);
	std::string auth_str = encode_auth(username, password);
	std::stringstream connect_stream;
	connect_stream << "CONNECT " <<
	                  remote_host << ":" << port_str <<
	                  " HTTP/1.0\r\n" <<
	                  "Host: " << remote_host << ":" << port_str << "\r\n" <<
	                  "Proxy-Authorization: Basic " << auth_str << "\r\n" <<
	                  "Content-Length: 0\r\n" <<
	                  "Connection: Keep-Alive\r\n" <<
	                  "Pragma: no-cache\r\n\r\n";
	std::string connect_string = connect_stream.str();

	LOG_INFO("Attempting to connect to proxy server %s:%u", proxy_host.c_str(), proxy_port);
	LOG_TRACE(connect_string);

	return connect(proxy_host, proxy_port, connect_string);
}

bool http_tunnel::is_resp_complete(const Poco::Buffer<char>& buf)
{
	// According to RFC 2616, the response will end with two CRLF sequences
	const char search_str[4] = {'\r', '\n', '\r', '\n'};
	for(uint32_t i = 4; i <= buf.size(); ++i)
	{
		if (memcmp(search_str, &buf[i - 4], 4) == 0)
		{
			return true;
		}
	}
	return false;
}


// I've made an effort to have this parser be RFC 2616 compliant, even though
// all we really care about is the response code.
//
// SP = 0x20 (ASCII space)
// HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
// Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
// After that, it's just headers (which we ignore)
http_tunnel::http_response http_tunnel::parse_resp(const Poco::Buffer<char>& buf)
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

	for (uint32_t i = 0; i < buf.size(); ++i)
	{
		char ch = buf[i];
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
				if (i < buf.size() + 1 && buf[i + 1] != '\n')
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
				if (i < buf.size() + 1 && buf[i + 1] != '\n')
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
