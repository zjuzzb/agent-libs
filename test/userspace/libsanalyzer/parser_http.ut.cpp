#include <gtest.h>
#include <string>
#include <vector>
#include <libsanalyzer/parser_http.h>


namespace {


sinsp_protocol_parser::msg_type should_parse(const std::string& value,
					     sinsp_http_parser& parser)
{
	return parser.should_parse(0 /* fdinfo unused */,
			       sinsp_partial_transaction::DIR_UNKNOWN /* dir unused*/,
			       true /*is_switched unused*/,
			       const_cast<char *>(value.c_str()),
			       value.length());
}

bool run_parser(const std::string& value, sinsp_http_parser& parser)
{
	sinsp_protocol_parser::msg_type mtype = should_parse(value, parser);

	bool success = false;
	if(sinsp_protocol_parser::MSG_REQUEST == mtype)
	{
		success = parser.parse_request(value.c_str(), value.length());
	}
	else if(sinsp_protocol_parser::MSG_RESPONSE == mtype)
	{
		success = parser.parse_response(value.c_str(), value.length());
	}

	return success;
}

}

TEST(parse_http_test, should_parse)
{
	{
		sinsp_http_parser parser;
		const std::string http_request = "HTTP/X.X abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_RESPONSE);
	}
	{
		// SMAGENT-1167
		// HTTP without the slash should not be recognized as a response
		sinsp_http_parser parser;
		const std::string http_request = "HTTP 200 abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_NONE);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "GET abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "POST abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "OPTIONS abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "HEAD abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "PUT abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "DELETE abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "TRACE abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
	{
		sinsp_http_parser parser;
		const std::string http_request = "CONNECT abc";
		sinsp_protocol_parser::msg_type type = should_parse(http_request, parser);
		EXPECT_EQ(type, sinsp_protocol_parser::MSG_REQUEST);
	}
}

TEST(parse_http_test, bad_status_code)
{
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 boat OK";
		bool success = run_parser(http_request, parser);
		EXPECT_FALSE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);

	}
}

TEST(parse_http_test, variety)
{
	// These were taken from http://www.ntu.edu.sg/home/ehchua/programming/webprogramming/http_basics.html
	// For completeness, every request/response from that page was added.
	// This should give us a decent set of "real world" tests.

	// Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
			"GET /docs/index.html HTTP/1.1\nHost: www.nowhere123.com\nAccept: image/gif, image/jpeg, */*\nAccept-Language: en-us\nAccept-Encoding: gzip, deflate\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("/docs/index.html"), result.path);
		EXPECT_EQ(std::string("gwww.nowhere123.com/docs/index.html"), result.url);
		EXPECT_EQ(std::string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"), result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 18 Oct 2009 08:56:53 GMT\nServer: Apache/2.2.14 (Win32)\nLast-Modified: Sat, 20 Nov 2004 07:16:26 GMT\nETag: \"10000000565a5-2c-3e94b66c2e680\"\nAccept-Ranges: bytes\nContent-Length: 44\nConnection: close\nContent-Type: text/html\nX-Pad: avoid browser bug\n\n<html><body><h1>It works!</h1></body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /index.html HTTP/1.0\n\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("g/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 18 Oct 2009 08:56:53 GMT\nServer: Apache/2.2.14 (Win32)\nLast-Modified: Sat, 20 Nov 2004 07:16:26 GMT\nETag: \"10000000565a5-2c-3e94b66c2e680\"\nAccept-Ranges: bytes\nContent-Length: 44\nConnection: close\nContent-Type: text/html\nX-Pad: avoid browser bug\n\n<html><body><h1>It works!</h1></body></html>\n\nConnection to host lost.";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// 501 Method Not Implemented Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "get /test.html HTTP/1.0\n";
		bool success = run_parser(http_request, parser);
		EXPECT_FALSE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// 501 Method Not Implemented Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 501 Method Not Implemented\nDate: Sun, 18 Oct 2009 10:32:05 GMT\nServer: Apache/2.2.14 (Win32)\nAllow: GET,HEAD,POST,OPTIONS,TRACE\nContent-Length: 215\nConnection: close\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>501 Method Not Implemented</title>\n</head><body>\n<h1>Method Not Implemented</h1>\n<p>get to /index.html not supported.<br />\n</p>\n</body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(501, result.status_code);
	}

	// 404 File Not Found Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /t.html HTTP/1.0\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("g/t.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// 404 File Not Found Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 404 Not Found\nDate: Sun, 18 Oct 2009 10:36:20 GMT\nServer: Apache/2.2.14 (Win32)\nContent-Length: 204\nConnection: close\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL /t.html was not found on this server.</p>\n</body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(404, result.status_code);
	}

	// Wrong HTTP Version Number Request
	// We don't detect this problem
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /index.html HTTTTTP/1.0\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("g/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Wrong HTTP Version Number Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 400 Bad Request\nDate: Sun, 08 Feb 2004 01:29:40 GMT\nServer: Apache/1.3.29 (Win32)\nConnection: close\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<HTML><HEAD>\n<TITLE>400 Bad Request</TITLE>\n</HEAD><BODY>\n<H1>Bad Request</H1>\nYour browser sent a request that this server could not understand.<P>\nThe request line contained invalid characters following the protocol string.<P><P>\n</BODY></HTML>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(400, result.status_code);
	}

	// Wrong Request-URI Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET test.html HTTP/1.0";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("gtest.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Wrong Request-URI Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 400 Bad Request\nDate: Sun, 18 Oct 2009 10:42:27 GMT\nServer: Apache/2.2.14 (Win32)\nContent-Length: 226\nConnection: close\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\n</p>\n</body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(400, result.status_code);
	}

	// Keep-Alive Connection Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /test.html HTTP/1.0\nConnection: Keep-Alive\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("g/test.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Keep-Alive Connection Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 18 Oct 2009 10:47:06 GMT\nServer: Apache/2.2.14 (Win32)\nLast-Modified: Sat, 20 Nov 2004 07:16:26 GMT\nETag: \"10000000565a5-2c-3e94b66c2e680\"\nAccept-Ranges: bytes\nContent-Length: 44\nKeep-Alive: timeout=5, max=100\nConnection: Keep-Alive\nContent-Type: text/html\n\n<html><body><h1>It works!</h1></body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// Accessing a Protected Resource Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /forbidden/index.html HTTP/1.0\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("g/forbidden/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Accessing a Protected Resource Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 403 Forbidden\nDate: Sun, 18 Oct 2009 11:58:41 GMT\nServer: Apache/2.2.14 (Win32)\nContent-Length: 222\nKeep-Alive: timeout=5, max=100\nConnection: Keep-Alive\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\n<p>You don't have permission to access /forbidden/index.html\non this server.</p>\n</body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(403, result.status_code);
	}

	// HTTP/1.1 Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /index.html HTTP/1.1\nHost: 127.0.0.1\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("/index.html"), result.path);
		EXPECT_EQ(std::string("g127.0.0.1/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// HTTP/1.1 Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 18 Oct 2009 12:10:12 GMT\nServer: Apache/2.2.14 (Win32)\nLast-Modified: Sat, 20 Nov 2004 07:16:26 GMT\nETag: \"10000000565a5-2c-3e94b66c2e680\"\nAccept-Ranges: bytes\nContent-Length: 44\nContent-Type: text/html\n\n<html><body><h1>It works!</h1></body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// HTTP/1.1 Missing Host Header Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /index.html HTTP/1.1\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("g/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// HTTP/1.1 Missing Host Header Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 400 Bad Request\nDate: Sun, 18 Oct 2009 12:13:46 GMT\nServer: Apache/2.2.14 (Win32)\nContent-Length: 226\nConnection: close\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\n</p>\n</body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(400, result.status_code);
	}

	// GET Request for Directory Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /testdir HTTP/1.1\nHost: 127.0.0.1\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("/testdir"), result.path);
		EXPECT_EQ(std::string("g127.0.0.1/testdir"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// GET Request for Directory Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 301 Moved Permanently\nDate: Sun, 18 Oct 2009 13:19:15 GMT\nServer: Apache/2.2.14 (Win32)\nLocation: http://127.0.0.1:8000/testdir/\nContent-Length: 238\nContent-Type: text/html; charset=iso-8859-1\n\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>301 Moved Permanently</title>\n</head><body>\n<h1>Moved Permanently</h1>\n<p>The document has moved <a href=\"http://127.0.0.1:8000/testdir/\">here</a>.</p>\n\n</body></html>";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(301, result.status_code);
	}

	// Issue a GET Request through a Proxy Server Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET http://www.amazon.com/index.html HTTP/1.1\nHost: www.amazon.com\nConnection: Close\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("http://www.amazon.com/index.html"), result.path);
		// Bad URL, tracked in SMAGENT-1215
		//EXPECT_EQ(std::string("ghttp://www.amazon.com/index.html"), result.m_url);
		EXPECT_EQ(std::string("gwww.amazon.comhttp://www.amazon.com/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Issue a GET Request through a Proxy Server Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 302 Found\nTransfer-Encoding: chunked\nDate: Fri, 27 Feb 2004 09:27:35 GMT\nContent-Type: text/html; charset=iso-8859-1\nConnection: close\nServer: Stronghold/2.4.2 Apache/1.3.6 C2NetEU/2412 (Unix)\nSet-Cookie: skin=; domain=.amazon.com; path=/; expires=Wed, 01-Aug-01 12:00:00 GMT\nConnection: close\nLocation: http://www.amazon.com:80/exec/obidos/subst/home/home.html\nVia: 1.1 xproxy (NetCache NetApp/5.3.1R4D5)\n\ned\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<HTML><HEAD>\n<TITLE>302 Found</TITLE>\n</HEAD><BODY>\n<H1>Found</H1>\nThe document has moved\n<A HREF=\"http://www.amazon.com:80/exec/obidos/subst/home/home.html\">\nhere</A>.<P>\n</BODY></HTML>\n\n0\n\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html; charset=iso-8859-1"), result.content_type);
		EXPECT_EQ(302, result.status_code);
	}

	// "HEAD" Request Method Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HEAD /index.html HTTP/1.0\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::HEAD, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(std::string("h/index.html"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// "HEAD" Request Method Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 18 Oct 2009 14:09:16 GMT\nServer: Apache/2.2.14 (Win32)\nLast-Modified: Sat, 20 Nov 2004 07:16:26 GMT\nETag: \"10000000565a5-2c-3e94b66c2e680\"\nAccept-Ranges: bytes\nContent-Length: 44\nConnection: close\nContent-Type: text/html\nX-Pad: avoid browser bug";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// "OPTIONS" Request Method Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "OPTIONS http://www.amazon.com/ HTTP/1.1\nHost: www.amazon.com\nConnection: Close\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::OPTIONS, result.method);
		EXPECT_EQ(std::string("http://www.amazon.com/"), result.path);
		// Bad URL, tracked in SMAGENT-1215
		//EXPECT_EQ(std::string("ohttp://www.amazon.com/"), parser.m_url);
		EXPECT_EQ(std::string("owww.amazon.comhttp://www.amazon.com/"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// "OPTIONS" Request Method Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Fri, 27 Feb 2004 09:42:46 GMT\nContent-Length: 0\nConnection: close\nServer: Stronghold/2.4.2 Apache/1.3.6 C2NetEU/2412 (Unix)\nAllow: GET, HEAD, POST, OPTIONS, TRACE\nConnection: close\nVia: 1.1 xproxy (NetCache NetApp/5.3.1R4D5)\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// "TRACE" Request Method Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "TRACE http://www.amazon.com/ HTTP/1.1\nHost: www.amazon.com\nConnection: Close\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::TRACE, result.method);
		EXPECT_EQ(std::string("http://www.amazon.com/"), result.path);
		// Bad URL, tracked in SMAGENT-1215
		//EXPECT_EQ(std::string("thttp://www.amazon.com/"), parser.m_url);
		EXPECT_EQ(std::string("twww.amazon.comhttp://www.amazon.com/"), result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// "TRACE" Request Method Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\nDate: Fri, 27 Feb 2004 09:44:21 GMT\nContent-Type: message/http\nConnection: close\nServer: Stronghold/2.4.2 Apache/1.3.6 C2NetEU/2412 (Unix)\nConnection: close\nVia: 1.1 xproxy (NetCache NetApp/5.3.1R4D5)\n\n9d\nTRACE / HTTP/1.1\nConnection: keep-alive\nHost: www.amazon.com\nVia: 1.1 xproxy (NetCache NetApp/5.3.1R4D5)\nX-Forwarded-For: 155.69.185.59, 155.69.5.234\n\n0\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("message/http"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// "POST" Request Method
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "POST /bin/login HTTP/1.1\nHost: 127.0.0.1:8000\nAccept: image/gif, image/jpeg, */*\nReferer: http://127.0.0.1:8000/login.html\nAccept-Language: en-us\nContent-Type: application/x-www-form-urlencoded\nAccept-Encoding: gzip, deflate\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\nContent-Length: 37\nConnection: Keep-Alive\nCache-Control: no-cache\n\nUser=Peter+Lee&pw=123456&action=login\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::POST, result.method);
		EXPECT_EQ(std::string("/bin/login"), result.path);
		EXPECT_EQ(std::string("p127.0.0.1:8000/bin/login"), result.url);
		EXPECT_EQ(std::string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"), result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// "POST" Request Method (upload)
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "POST /bin/upload HTTP/1.1\nHost: test101\nAccept: image/gif, image/jpeg, */*\nAccept-Language: en-us\nContent-Type: multipart/form-data; boundary=---------------------------7d41b838504d8\nAccept-Encoding: gzip, deflate\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\nContent-Length: 342\nConnection: Keep-Alive\nCache-Control: no-cache\n\n-----------------------------7d41b838504d8 Content-Disposition: form-data; name=\"username\"\nPeter Lee\n-----------------------------7d41b838504d8 Content-Disposition: form-data; name=\"fileID\"; filename=\"C:\temp.html\" Content-Type: text/plain\n<h1>Home page on main server</h1>\n-----------------------------7d41b838504d8--";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::POST, result.method);
		EXPECT_EQ(std::string("/bin/upload"), result.path);
		EXPECT_EQ(std::string("ptest101/bin/upload"), result.url);
		EXPECT_EQ(std::string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"), result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// "CONNECT" Request Method
	{
		// No example for this
	}

	// Content-Type Negotiation Request 1
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /logo HTTP/1.1\nAccept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg,\n  application/x-shockwave-flash, application/vnd.ms-excel, \n  application/vnd.ms-powerpoint, application/msword, */*\nAccept-Language: en-us\nAccept-Encoding: gzip, deflate\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\nHost: test101:8080\nConnection: Keep-Alive";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("/logo"), result.path);
		EXPECT_EQ(std::string("gtest101:8080/logo"), result.url);
		EXPECT_EQ(std::string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"), result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Content-Type Negotiation Response 1
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 29 Feb 2004 01:42:22 GMT\nServer: Apache/1.3.29 (Win32)\nContent-Location: logo.gif\nVary: negotiate,accept\nTCN: choice\nLast-Modified: Wed, 21 Feb 1996 19:45:52 GMT\nETag: \"0-916-312b7670;404142de\"\nAccept-Ranges: bytes\nContent-Length: 2326\nKeep-Alive: timeout=15, max=100\nConnection: Keep-Alive\nContent-Type: image/gif\n\n(body omitted)\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("image/gif"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// Content-Type Negotiation Request 2
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /logo HTTP/1.1\nAccept: */*\nAccept-Language: en-us\nAccept-Encoding: gzip, deflate\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\nHost: test101:8080\nConnection: Keep-Alive\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("/logo"), result.path);
		EXPECT_EQ(std::string("gtest101:8080/logo"), result.url);
		EXPECT_EQ(std::string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"), result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Content-Type Negotiation Response 2
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 29 Feb 2004 01:48:16 GMT\nServer: Apache/1.3.29 (Win32)\nContent-Location: logo.html\nVary: negotiate,accept\nTCN: choice\nLast-Modified: Fri, 20 Feb 2004 04:31:17 GMT\nETag: \"0-10-40358d95;404144c1\"\nAccept-Ranges: bytes\nContent-Length: 16\nKeep-Alive: timeout=15, max=100\nConnection: Keep-Alive\nContent-Type: text/html\n\n(body omitted)";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}

	// Language Negotiation and "Options MultiView" Request
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "GET /index.html HTTP/1.1\nAccept: */*\nAccept-Language: en-us\nAccept-Encoding: gzip, deflate\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\nHost: test101:8080\nConnection: Keep-Alive\n";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_TRUE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::GET, result.method);
		EXPECT_EQ(std::string("/index.html"), result.path);
		EXPECT_EQ(std::string("gtest101:8080/index.html"), result.url);
		EXPECT_EQ(std::string("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"), result.agent);

		// Response result
		EXPECT_FALSE(parser.m_is_valid);
		EXPECT_EQ(nullptr, result.content_type);
		EXPECT_EQ(0, result.status_code);
	}

	// Language Negotiation and "Options MultiView" Response
	{
		sinsp_http_parser parser;
		const std::string http_request =
		   "HTTP/1.1 200 OK\nDate: Sun, 29 Feb 2004 02:08:29 GMT\nServer: Apache/1.3.29 (Win32)\nContent-Location: index.html.en\nVary: negotiate\nTCN: choice\nLast-Modified: Sun, 29 Feb 2004 02:07:45 GMT\nETag: \"0-13-40414971;40414964\"\nAccept-Ranges: bytes\nContent-Length: 19\nKeep-Alive: timeout=15, max=100\nConnection: Keep-Alive\nContent-Type: text/html\nContent-Language: en\n\n(body omitted)";
		bool success = run_parser(http_request, parser);
		EXPECT_TRUE(success);
		const sinsp_http_parser::Result& result = parser.result();

		// Request result
		EXPECT_FALSE(parser.m_is_req_valid);
		EXPECT_EQ(sinsp_http_parser::http_method::NONE, result.method);
		EXPECT_EQ(nullptr, result.path);
		EXPECT_EQ(nullptr, result.url);
		EXPECT_EQ(nullptr, result.agent);

		// Response result
		EXPECT_TRUE(parser.m_is_valid);
		EXPECT_EQ(std::string("text/html"), result.content_type);
		EXPECT_EQ(200, result.status_code);
	}
}
