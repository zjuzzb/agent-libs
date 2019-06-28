/**
 * @file
 *
 * Unit tests for fault_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include "fault_handler.h"
#include "fault_rest_request_handler.h"
#include <memory>
#include <gtest.h>

using dragent::fault_rest_request_handler;
using userspace_shared::fault_handler;
using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

/**
 * Ensure that get_path() returns the expected path.
 */
TEST(fault_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/fault_injection",
	          fault_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path() returns the expected path.
 */
TEST(fault_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/fault_injection",
	          fault_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns non-nullptr.
 */
TEST(fault_rest_request_handler_test, create)
{
	std::unique_ptr<fault_rest_request_handler> handler(
			fault_rest_request_handler::create());

	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that if we can't parse off a fault name in the URI for a GET request,
 * that the handler returns an error document.
 */
TEST(fault_rest_request_handler_test, GET_no_fault_name_returns_error)
{
	const std::string path = "";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;
	const std::string expected_response = R"EOF({
   "error" : "Fault injection point name not found in URL"
}
)EOF";
	dummy_server_request request(path);
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if a client performs a GET request for a fault injection point
 * that does not exist, the handler returns an appropriate error document.
 */
TEST(fault_rest_request_handler_test, GET_fault_not_found)
{
	const std::string path = "/api/fault-injection/this.fault.does.not.exist";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	const std::string expected_response = R"EOF({
   "error" : "Fault injection point 'this.fault.does.not.exist' not found"
}
)EOF";
	dummy_server_request request(path);
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if a client requests a fault injection point that exists, the
 * handler returns a JSON representation of that fault handler.
 */
TEST(fault_rest_request_handler_test, GET_fault_found)
{
	const std::string path = "/api/fault-injection/fault.name";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

	fault_handler fh("file", 42, "fault.name", "description");
	dummy_server_request request(path);
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(fh.to_json(), response.m_stream.str());
}

/**
 * Ensure that if we can't parse off a fault name in the URI for a PUT request,
 * that the handler returns an error document.
 */
TEST(fault_rest_request_handler_test, PUT_no_fault_name_returns_error)
{
	const std::string path = "";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;
	const std::string expected_response = R"EOF({
   "error" : "Fault injection point name not found in URL"
}
)EOF";
	dummy_server_request request(path);
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if a client performs a PUT request for a fault injection point
 * that does not exist, the handler returns an appropriate error document.
 */
TEST(fault_rest_request_handler_test, PUT_fault_not_found)
{
	const std::string path = "/api/fault-injection/this.fault.does.not.exist";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	const std::string expected_response = R"EOF({
   "error" : "Fault injection point 'this.fault.does.not.exist' not found"
}
)EOF";
	dummy_server_request request(path);
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if a client performs a PUT request with a body that isn't
 * valid JSON, the handler returns an appropriate error document.
 */
TEST(fault_rest_request_handler_test, PUT_body_not_json)
{
	const std::string path = "/api/fault-injection/fault.name";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;

	fault_handler fh("file", 42, "fault.name", "description");
	dummy_server_request request(path, "this is not json");
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_NE(std::string::npos,
	          response.m_stream.str().find(
	          	  "fault_handler::exception: Body contains malformed JSON"));
}

/**
 * Ensure that if a client PUTs a properly-formatted JSON document for a valid
 * fault injection point, that the call updates the state of the fault
 * injection point.
 */
TEST(fault_rest_request_handler_test, PUT_valid_update)
{
	const std::string path = "/api/fault-injection/fault.name";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string expected_response = R"EOF({
}
)EOF";
	const std::string body = R"EOF({
    "enabled":      true,
    "fault_string": "These are the voyages of the starship Enterprise",
    "fault_uint64": 987,
    "mode":         "ONE_SHOT",
    "n_count":      19,
    "probability":  27
}
)EOF";
	fault_handler fh("file", 42, "fault.name", "description");
	dummy_server_request request(path, body);
	dummy_server_response response;
	fault_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(fh.to_json(), response.m_stream.str());

	// Make sure that the fault handler was updated
	ASSERT_TRUE(fh.is_enabled());
	ASSERT_EQ("These are the voyages of the starship Enterprise",
	          fh.get_fault_string());
	ASSERT_EQ(987, fh.get_fault_uint64());
	ASSERT_EQ(fault_handler::fault_mode::ONE_SHOT, fh.get_fault_mode());
	ASSERT_EQ(19, fh.get_n_count());
	ASSERT_EQ(27, fh.get_fault_probability());
}

#endif // defined(FAULT_INJECTION_ENABLED)
