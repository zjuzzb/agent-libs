/**
 * @file
 *
 * Unit tests for webpage_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "webpage_rest_request_handler.h"
#include <gtest.h>
#include <memory>
#include <dummy_server_request.h>
#include <dummy_server_response.h>
#include <rest_util.h>

using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

using namespace dragent;

/**
 * Ensure that get_path() returns the expected path.
 */
TEST(webpage_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/", webpage_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path returns the expected path.
 */
TEST(webpage_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/v0",
		  webpage_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns a non-null pointer.
 */
TEST(webpage_rest_request_handler_test, create)
{
	std::shared_ptr<webpage_rest_request_handler> handler(
	   webpage_rest_request_handler::create());
	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that we get something that looks like a webpage. This is a weak
 * test that just verifies we are getting something.
 */
TEST(webpage_rest_request_handler_test, GET_webpage)
{
	const std::string path = webpage_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string expected_content_type = "text/html";

	dummy_server_request request(path);
	dummy_server_response response;
	webpage_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_content_type, response.getContentType());
	ASSERT_EQ(expected_status, response.getStatus());

	// Ensure it contains the start of a <body> tag
	ASSERT_NE(std::string::npos, response.m_stream.str().find("<body"));
}
