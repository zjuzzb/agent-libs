/**
 * @file
 *
 * Unit tests for file_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "file_rest_request_handler.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include <rest_util.h>
#include <scoped_temp_file.h>
#include <fstream>
#include <gtest.h>
#include <memory>

using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;
using test_helpers::scoped_temp_file;

using namespace dragent;

/**
 * Ensure that get_path() returns the expected path.
 */
TEST(file_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/file", file_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path returns the expected path.
 */
TEST(file_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/file",
		  file_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns a non-null pointer.
 */
TEST(file_rest_request_handler_test, create)
{
	std::shared_ptr<file_rest_request_handler> handler(
	   file_rest_request_handler::create());
	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that we can fetch a text file by name using the non-versioned
 * path.
 */
TEST(file_rest_request_handler_test, GET_existing_text_file_via_path)
{
	scoped_temp_file file("" /*content*/, "txt");
	std::string expected_response = "Moses supposes his toeses are roses.";

	{
		std::ofstream myfile;
		myfile.open(file.get_filename());
		myfile << expected_response;
		myfile.close();
	}

	const std::string path = file_rest_request_handler::get_path() +
				 "/" + librest::post_last_slash(file.get_filename());
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string expected_content_type = "text/plain";

	dummy_server_request request(path);
	dummy_server_response response;
	file_rest_request_handler handler({file.get_filename()});

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_response, response.m_stream.str());
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_content_type, response.getContentType());
}

/**
 * Ensure that an empty file gives the right response
 */
TEST(file_rest_request_handler_test, GET_empty_file)
{
	const std::string path = file_rest_request_handler::get_versioned_path() +
				 "/";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;
	const std::string expected_content_type = "application/json";
	const std::string expected_response = "{ \"error\": \"Empty file not allowed\" }";

	dummy_server_request request(path);
	dummy_server_response response;
	file_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_content_type, response.getContentType());
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that a non-existing file gives the right response
 */
TEST(file_rest_request_handler_test, GET_file_name_not_found)
{
	const std::string path = file_rest_request_handler::get_versioned_path() +
				 "/not_a_registered_file";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	const std::string expected_content_type = "application/json";
	const std::string expected_response = "{ \"error\": \"File not_a_registered_file in cannot be returned\" }";

	dummy_server_request request(path);
	dummy_server_response response;
	file_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_content_type, response.getContentType());
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}
