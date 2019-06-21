/**
 * @file
 *
 * Unit tests for configlist_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "configlist_rest_request_handler.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include "type_config.h"
#include <memory>
#include <gtest.h>

using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

using namespace dragent;

/**
 * Ensure that get_path() returns the expected path.
 */
TEST(configlist_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/configs",
	          configlist_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path() returns the expected path.
 */
TEST(configlist_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/configs",
	          configlist_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns non-nullptr
 */
TEST(configlist_rest_request_handler_test, create)
{
	std::unique_ptr<configlist_rest_request_handler> handler(
			configlist_rest_request_handler::create());

	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that the document returned on GET on the path includes configs.  It
 * should include all configs.  This test creates a couple and ensures that the
 * returned document includes those configs.
 */
TEST(configlist_rest_request_handler_test, path_contains_configs)
{
	const std::string path = configlist_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

	type_config<bool> config1(false, "some description", "ut-test-key-1");
	type_config<int> config2(27, "some other description", "ut-test-key-2");

	dummy_server_request request(path);
	dummy_server_response response;
	configlist_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	const std::string response_str = response.m_stream.str();
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_NE(response_str.find("ut-test-key-1"), std::string::npos);
	ASSERT_NE(response_str.find("some description"), std::string::npos);
	ASSERT_NE(response_str.find("false"), std::string::npos);

	ASSERT_NE(response_str.find("ut-test-key-2"), std::string::npos);
	ASSERT_NE(response_str.find("some other description"), std::string::npos);
	ASSERT_NE(response_str.find("27"), std::string::npos);
}

/**
 * Ensure that the document returned on GET on the versioned path includes
 * configs.  It should include all configs.  This test creates a couple and
 * ensures that the returned document includes those configs.
 */
TEST(configlist_rest_request_handler_test, versioned_path_contains_configs)
{
	const std::string path = configlist_rest_request_handler::get_versioned_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

	type_config<bool> config1(false, "some description", "ut-test-key-1");
	type_config<int> config2(27, "some other description", "ut-test-key-2");

	dummy_server_request request(path);
	dummy_server_response response;
	configlist_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	const std::string response_str = response.m_stream.str();
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_NE(response_str.find("ut-test-key-1"), std::string::npos);
	ASSERT_NE(response_str.find("some description"), std::string::npos);
	ASSERT_NE(response_str.find("false"), std::string::npos);

	ASSERT_NE(response_str.find("ut-test-key-2"), std::string::npos);
	ASSERT_NE(response_str.find("some other description"), std::string::npos);
	ASSERT_NE(response_str.find("27"), std::string::npos);
}
