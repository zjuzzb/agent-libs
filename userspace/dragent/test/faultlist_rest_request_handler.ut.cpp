/**
 * @file
 *
 * Unit tests for faultlist_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include "faultlist_rest_request_handler.h"
#include "fault_handler.h"
#include <memory>
#include <gtest.h>

using dragent::faultlist_rest_request_handler;
using userspace_shared::fault_handler;
using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

/**
 * Ensure that get_path() returns the correct path.
 */
TEST(faultlist_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/fault_injections",
	          faultlist_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path() returns the correct path.
 */
TEST(faultlist_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/fault_injections",
	          faultlist_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns non-nullptr.
 */
TEST(faultlist_rest_request_handler_test, create)
{
	std::unique_ptr<faultlist_rest_request_handler> handler(
			faultlist_rest_request_handler::create());

	ASSERT_NE(handler.get(), nullptr);
}

/**
 * Ensure that a GET request to the handler returns a list of all registered
 * faults in JSON format.
 */
TEST(faultlist_rest_request_handler_test, GET_returns_list_of_registered_faults)
{
	const std::string path = "/api/fault-injections";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

	fault_handler fh1("file1",  42, "fault.name.1", "description1");
	fault_handler fh2("file2", 187, "fault.name.2", "description2");
	dummy_server_request request(path);
	dummy_server_response response;
	faultlist_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());

	const std::string response_string = response.m_stream.str();

	// Rather than trying to parse the JSON, just check that the
	// expected strings are in the document.
	ASSERT_NE(std::string::npos, response_string.find("file1"));
	ASSERT_NE(std::string::npos, response_string.find("42"));
	ASSERT_NE(std::string::npos, response_string.find("fault.name.1"));
	ASSERT_NE(std::string::npos, response_string.find("description1"));

	ASSERT_NE(std::string::npos, response_string.find("file2"));
	ASSERT_NE(std::string::npos, response_string.find("187"));
	ASSERT_NE(std::string::npos, response_string.find("fault.name.2"));
	ASSERT_NE(std::string::npos, response_string.find("description2"));
}

#endif // defined(FAULT_INJECTION_ENABLED)
