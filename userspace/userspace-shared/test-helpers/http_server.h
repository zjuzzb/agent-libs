#pragma once

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerRequestImpl.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/ServerSocket.h>

#include <cstdint>
#include <iostream>
#include <memory>

namespace test_helpers
{
///
/// Sample HTTP handler class
///
/// Implements a very simple request handler
///
class HTTPHandler : public Poco::Net::HTTPRequestHandler
{
public:
	virtual void handleRequest(Poco::Net::HTTPServerRequest& request,
	                           Poco::Net::HTTPServerResponse& response) override
	{
		response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
		response.setContentType("text/html");

		std::ostream& out = response.send();
		out << "<html><body>"
		    << "<h1>Sysdig agent test</h1>"
		    << "<p>Request host = " << request.getHost() << "</p>"
		    << "<p>Request URI = " << request.getURI() << "</p>"
		    << "</body></html>" << std::flush;
	}
};

///
/// Sample request handler factory for a trivial HTTP request handler
///
class HTTPRHFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
	static const uint16_t port = 9090;
	static const uint16_t secure_port = 443;  // The proto analyzer will barf if it's a wonky port
	virtual HTTPHandler* createRequestHandler(const Poco::Net::HTTPServerRequest&)
	{
		return new HTTPHandler();
	}
};

///
/// Starts an HTTP server listening on localhost upon instantiation.
///
class scoped_http_server
{
public:
	scoped_http_server(uint16_t port = 9090);
	scoped_http_server(Poco::Net::HTTPRequestHandlerFactory::Ptr fact);
	scoped_http_server(uint16_t port,
	                   Poco::Net::HTTPRequestHandlerFactory::Ptr fact);

	~scoped_http_server();

	///
	/// Make an HTTP request to the loopback IP
	///
	/// This function knows how to connect to the containing server class and provides
	/// a convenient interface for making a simple request (assuming we don't care
	/// about the response).
	///
	/// It will block until the response is received.
	///
	/// @return  true   The request was made successfully
	/// @return  false  The request failed before it could be made
	///
	static bool localhost_http_request(uint16_t port);

private:
	Poco::Net::HTTPServer m_srv;
};

} // namespace test_helpers
