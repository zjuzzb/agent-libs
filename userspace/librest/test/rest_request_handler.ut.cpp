/**
 * @file
 *
 * Unit tests for rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_request_handler.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include <gtest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTTPServerRequest.h>

using namespace librest;
using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

namespace
{

const std::string DEFAULT_PATH = "/some/path";
const std::string DEFAULT_NAME = "handler name";
const std::string DEFAULT_DESCRIPTION = "handler description";

/**
 * A custom rest_request_handler.  Each of the different handle_XXX_request
 * methods succeeds or fails with different behaviors.
 */
class custom_rest_request_handler : public rest_request_handler
{
public:
	const static std::string SUCCESS;
	const static std::string PUT_ERROR;
	const static std::string REQUEST_COMPLETE_ERROR;

	custom_rest_request_handler(const bool request_complete_failure = false):
		rest_request_handler(DEFAULT_PATH,
		                     DEFAULT_NAME,
		                     DEFAULT_DESCRIPTION),
		m_request_complete_failure(request_complete_failure)
	{ }

protected:
	/**
	 * Returns SUCCESS.
	 */
	std::string handle_get_request(
			Poco::Net::HTTPServerRequest& request,
			Poco::Net::HTTPServerResponse& response) override
	{
		return SUCCESS;
	}

	/**
	 * Throws a std::runtime_error
	 */
	std::string handle_put_request(
			Poco::Net::HTTPServerRequest& request,
			Poco::Net::HTTPServerResponse& response) override
	{
		throw std::runtime_error(PUT_ERROR);
	}

	/**
	 * Throws an int
	 */
	std::string handle_post_request(
			Poco::Net::HTTPServerRequest& request,
			Poco::Net::HTTPServerResponse& response) override
	{
		throw 42;
	}

	/**
	 * Throws a std::runtime_error if m_request_complete_failure is true.
	 */
	void request_complete(Poco::Net::HTTPServerRequest& request) override
	{
		// Since the superclass' version is concrete, we call-through
		// to it (even though it currently doesn't do anything)
		rest_request_handler::request_complete(request);

		if(m_request_complete_failure)
		{
			throw std::runtime_error(REQUEST_COMPLETE_ERROR);
		}
	}

private:
	const bool m_request_complete_failure;
};
const std::string custom_rest_request_handler::SUCCESS = "{ \"status\": \"SUCCESS\" }";
const std::string custom_rest_request_handler::PUT_ERROR = "Ouch";
const std::string custom_rest_request_handler::REQUEST_COMPLETE_ERROR = "Double ouch";

/**
 * Build and return a properly-formatted error string.
 */
std::string build_error(const std::string& msg)
{
	return std::string("{ \"error\": \"") + msg + "\" }";
}
/**
 * Build and return a properly-formatted "not implemented" error string.
 */
std::string build_not_implemented_error(const std::string& method)
{
	return build_error(method + " not implemented");
}

} // end namespace

/**
 * Ensure that a rest_request_handler is in the expected initial state.
 */
TEST(rest_request_handler_test, initial_state)
{
	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);

	ASSERT_EQ(DEFAULT_PATH, handler.get_path());
	ASSERT_EQ(DEFAULT_NAME, handler.get_name());
	ASSERT_EQ(DEFAULT_DESCRIPTION, handler.get_description());
}

/**
 * Ensure that the default response to a GET request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, get_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response content type is "application/json".
 */
TEST(rest_request_handler_test, response_content_type_json)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string content_type = "application/json";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(content_type, response.getContentType());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a PUT request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, put_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a POST request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, post_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_POST;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a PATCH request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, patch_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PATCH;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a DELETE request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, delete_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_DELETE;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a OPTIONS request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, options_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_OPTIONS;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a CONNECT request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, connect_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_CONNECT;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a HEAD request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, head_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_HEAD;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a TRACE request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, trace_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_TRACE;
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the default response to a custom request is a "not implemented"
 * response.
 */
TEST(rest_request_handler_test, custom_request)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED;
	const std::string& method = "UBER_SYSDIG_METHOD";
	const std::string expected = build_not_implemented_error(method);

	rest_request_handler handler(DEFAULT_PATH, DEFAULT_NAME, DEFAULT_DESCRIPTION);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(expected, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the handler returns the expected response on success.
 */
TEST(rest_request_handler_test, custom_get_success)
{
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;

	custom_rest_request_handler handler;
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	handler.handleRequest(request, response);

	ASSERT_EQ(custom_rest_request_handler::SUCCESS, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
}

/**
 * Ensure that the handler does not catch std::exception%s
 */
TEST(rest_request_handler_test, custom_put_runtime_error)
{
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;

	custom_rest_request_handler handler;
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	ASSERT_THROW(handler.handleRequest(request, response), std::exception);
}

/**
 * Ensure that the handler doesn't catch "unknown" exceptions (here, and int)
 */
TEST(rest_request_handler_test, custom_post_unknown_exception)
{
	const std::string& method = Poco::Net::HTTPRequest::HTTP_POST;

	custom_rest_request_handler handler;
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	ASSERT_ANY_THROW(handler.handleRequest(request, response));
}

/**
 * Ensure that if request_complete() throws an exception, that exception is
 * not caught by the framework.
 */
TEST(rest_request_handler_test, request_complete_error_does_not_cause_failure)
{
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;

	const bool trigger_request_complete_failure = true;
	custom_rest_request_handler handler(trigger_request_complete_failure);
	dummy_server_request request(DEFAULT_PATH);
	dummy_server_response response;

	request.setMethod(method);
	ASSERT_ANY_THROW(handler.handleRequest(request, response));
}
