/**
 * @file
 *
 * Unit tests for rest_request_handler_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_request_handler_factory.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include <assert.h>
#include <istream>
#include <sstream>
#include <stdexcept>
#include <gtest.h>
#include <Poco/Net/SocketAddress.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>

using namespace librest;
using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

namespace
{

/**
 * A test, do-nothing implementation of the HTTPRequestHandler interface.
 */
class test_request_handler : public Poco::Net::HTTPRequestHandler
{
public:
	void handleRequest(Poco::Net::HTTPServerRequest& request,
	                   Poco::Net::HTTPServerResponse& response) override
	{ }

	/**
	 * Factory function for creating instances of test_request_handler.
	 */
	static test_request_handler* create()
	{
		return new test_request_handler();
	}

private:
	// Make clients use the factory function
	test_request_handler() = default;

};

} // end namespace

/**
 * Ensure that createRequestHandler() with a request whose URI doesn't
 * match a registered handler returns a handler that results in 404.
 */
TEST(rest_request_handler_factory_test, unknown_path_null_request_handler)
{
	rest_request_handler_factory factory;
	dummy_server_request request("/this/is/some/example/path/");
	Poco::Net::HTTPRequestHandler* handler = factory.createRequestHandler(request);

	ASSERT_NE(handler, nullptr);

	dummy_server_request request2("/my/uri");
	dummy_server_response response;
	handler->handleRequest(request2, response);

	ASSERT_EQ(Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND,
	          response.getStatus());
}

/**
 * Ensure that createRequestHandler() with a request whose URI doesn't
 * match a registered handler (and whose URI is missing a leading slash)
 * returns a handler that results in 404.
 */
TEST(rest_request_handler_factory_test, path_missing_leading_slash_null_request_handler)
{
	rest_request_handler_factory factory;
	dummy_server_request request("this/is/some/example/path/");
	Poco::Net::HTTPRequestHandler* handler = factory.createRequestHandler(request);

	ASSERT_NE(handler, nullptr);

	dummy_server_request request2("/my/uri");
	dummy_server_response response;
	handler->handleRequest(request2, response);

	ASSERT_EQ(Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND,
	          response.getStatus());
}

/**
 * Ensure that createRequestHandler() with a request whose URI matches a
 * registered handler with the exact path returns a new instance of the
 * given handler.
 */
TEST(rest_request_handler_factory_test, registered_path_handler_valid)
{
	const std::string path = "/some/valid/path";
	rest_request_handler_factory factory;
	dummy_server_request request(path);

	factory.register_path_handler(path, test_request_handler::create);

	Poco::Net::HTTPRequestHandler* handler = factory.createRequestHandler(request);
	ASSERT_NE(handler, nullptr);

	// Make sure it's the right type
	test_request_handler* trh = dynamic_cast<test_request_handler*>(handler);
	ASSERT_NE(trh, nullptr);
}

/**
 * Ensure that createRequestHandler() with a request whose URI matches a
 * registered handler with a matching path prefix returns a new instance
 * of the given handler.
 */
TEST(rest_request_handler_factory_test, registered_prefix_path_handler_valid)
{
	const std::string prefix = "/some/valid/path";
	const std::string path = prefix + "/with/a/suffix/";
	rest_request_handler_factory factory;
	dummy_server_request request(path);

	factory.register_path_handler(prefix, test_request_handler::create);

	Poco::Net::HTTPRequestHandler* handler = factory.createRequestHandler(request);
	ASSERT_NE(handler, nullptr);

	// Make sure it's the right type
	test_request_handler* trh = dynamic_cast<test_request_handler*>(handler);
	ASSERT_NE(trh, nullptr);
}
