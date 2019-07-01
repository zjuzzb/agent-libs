/**
 * @file
 *
 * Unit tests for config_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_rest_request_handler.h"
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
TEST(config_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/config", config_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path returns the expected path.
 */
TEST(config_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/config",
	          config_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns a non-null pointer.
 */
TEST(config_rest_request_handler_test, create)
{
	std::shared_ptr<config_rest_request_handler> handler(
			config_rest_request_handler::create());
	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that we can fetch a config item by name using the non-versioned
 * path.
 */
TEST(config_rest_request_handler_test, GET_existing_config_via_path)
{
	const std::string path = config_rest_request_handler::get_path() +
	                         "/ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string expected_response = R"EOF({
   "ut-test-key" : {
      "description" : "some description",
      "value" : "false"
   }
}
)EOF";

	type_config<bool> config(false, "some description", "ut-test-key");

	dummy_server_request request(path);
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that we can fetch a config item by name using the versioned
 * path.
 */
TEST(config_rest_request_handler_test, GET_existing_config_via_versioned_path)
{
	const std::string path = config_rest_request_handler::get_versioned_path() +
	                         "/ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string expected_response = R"EOF({
   "ut-test-key" : {
      "description" : "some description",
      "value" : "false"
   }
}
)EOF";

	type_config<bool> config(false, "some description", "ut-test-key");

	dummy_server_request request(path);
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if the URI doesn't include any slash (which Poco might not
 * actually allow, but...), the config_rest_request_handler returns the
 * expected result.
 */
TEST(config_rest_request_handler_test, GET_no_slash_bad_request)
{
	const std::string path = config_rest_request_handler::get_versioned_path() +
	                         "/ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;
	const std::string expected_response = R"EOF({
   "error" : "Configuration option name not found"
}
)EOF";

	type_config<bool> config(false, "some description", "ut-test-key");

	dummy_server_request request(""); // <- no slash
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if a client requests a config key that does not exist, we
 * get 404 with the expected error message.
 */
TEST(config_rest_request_handler_test, GET_config_name_not_found)
{
	const std::string path = config_rest_request_handler::get_versioned_path() +
	                         "/missing-ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	const std::string expected_response = R"EOF({
   "error" : "Configuration option 'missing-ut-test-key' not found"
}
)EOF";

	dummy_server_request request(path);
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that we can PUT a config item by name using the non-versioned
 * path.
 */
TEST(config_rest_request_handler_test, PUT_existing_config_via_path)
{
	const std::string path = config_rest_request_handler::get_path() +
	                         "/ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::string body = R"EOF({ "value": "true" })EOF";
	const std::string expected_response = R"EOF({
   "ut-test-key" : {
      "description" : "some description",
      "value" : "true"
   }
}
)EOF";

	type_config<bool> config(false, "some description", "ut-test-key");

	dummy_server_request request(path, body);
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that we can PUT a config item using malformed JSON, we get an
 * appropriate error response.
 */
TEST(config_rest_request_handler_test, PUT_existing_config_bad_json)
{
	const std::string path = config_rest_request_handler::get_path() +
	                         "/ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;
	const std::string body = R"EOF(this is not json)EOF";
	const std::string expected_response = R"EOF({
   "error" : "configuration_unit::exception: Failed to parse json"
}
)EOF";

	type_config<bool> config(false, "some description", "ut-test-key");

	dummy_server_request request(path, body);
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if the URI doesn't include any slash (which Poco might not
 * actually allow, but...), the config_rest_request_handler returns the
 * expected result on a PUT.
 */
TEST(config_rest_request_handler_test, PUT_no_slash_bad_request)
{
	const std::string path = config_rest_request_handler::get_versioned_path() +
	                         "/ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST;
	const std::string expected_response = R"EOF({
   "error" : "Configuration option name not found"
}
)EOF";

	type_config<bool> config(false, "some description", "ut-test-key");

	dummy_server_request request(""); // <- no slash
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Ensure that if a client PUTs a config key that does not exist, we
 * get 404 with the expected error message.
 */
TEST(config_rest_request_handler_test, PUT_config_name_not_found)
{
	const std::string path = config_rest_request_handler::get_versioned_path() +
	                         "/missing-ut-test-key";
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	const std::string expected_response = R"EOF({
   "error" : "Configuration option 'missing-ut-test-key' not found"
}
)EOF";

	dummy_server_request request(path);
	dummy_server_response response;
	config_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}
