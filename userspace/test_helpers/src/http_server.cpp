#include "http_server.h"

#include "Poco/Exception.h"
#include "Poco/NullStream.h"
#include "Poco/URI.h"
#include "Poco/URIStreamOpener.h"
#include "Poco/SharedPtr.h"

#include <Poco/PipeStream.h>

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerRequestImpl.h>
#include <Poco/Net/HTTPServerResponse.h>
#include "Poco/Net/HTTPStreamFactory.h"
#include <Poco/Net/ServerSocket.h>

#include <cstdint>
#include <sstream>
#include <iostream>
#include <thread>

namespace test_helpers
{

scoped_http_server::scoped_http_server(uint16_t port)
    : scoped_http_server(port, new HTTPRHFactory)
{
}

scoped_http_server::scoped_http_server(Poco::Net::HTTPRequestHandlerFactory::Ptr fact)
    : scoped_http_server(9090, fact)
{
}

scoped_http_server::scoped_http_server(uint16_t port,
                                       Poco::Net::HTTPRequestHandlerFactory::Ptr fact)
    : m_srv(fact, Poco::Net::ServerSocket(port), new Poco::Net::HTTPServerParams)
{
	m_srv.start();
}

scoped_http_server::~scoped_http_server()
{
	m_srv.stopAll(true);
}

bool scoped_http_server::localhost_http_request(uint16_t port)
{
	try
	{
		Poco::Net::HTTPClientSession session("http://127.0.0.1", port);
		Poco::Net::HTTPRequest request(Poco::Net::HTTPRequest::HTTP_GET);
		Poco::Net::HTTPResponse response;
		session.sendRequest(request);
		session.receiveResponse(response);
	}
	catch (const Poco::Exception& ex)
	{
		std::cerr << "Exception: " << ex.displayText() << std::endl;
		return false;
	}
	return true;
}

} // namespace test_helpers
