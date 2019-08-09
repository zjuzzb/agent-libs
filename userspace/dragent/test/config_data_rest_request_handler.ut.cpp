/**
 * @file
 *
 * Unit tests for config_data_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_data_rest_request_handler.h"
#include "connection_manager.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include <memory>
#include <string>
#include <gtest.h>

using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;

using namespace dragent;

namespace
{

/**
 * Dummy realization of the message_handler.  handle_config_data
 * does nothing, and returns the value passed to the constructor.
 */
class dummy_config_data_message_handler : public connection_manager::message_handler
{
public:
	dummy_config_data_message_handler(const bool success = true):
		m_success(success)
	{ }

	bool handle_message(const draiosproto::message_type,
	                    uint8_t* const,
	                    const size_t) override
	{
		return m_success;
	}

private:
	const bool m_success;
};

/**
 * RAII wrapper around {get,set}_config_data_message_handler.  Saves the
 * current handler on construction, restores it on destruction.
 */
class scoped_config_data_rest_request_message_handler
{
public:
	scoped_config_data_rest_request_message_handler():
		m_old(config_data_rest_request_handler::get_config_data_message_handler())
	{ }

	~scoped_config_data_rest_request_message_handler()
	{
		config_data_rest_request_handler::set_config_data_message_handler(m_old);
	}

private:
	connection_manager::message_handler::ptr m_old;
};

} // end namespace

/**
 * Ensure that get_path() returns the expected path.
 */
TEST(config_data_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/protobuf/config_data",
	          config_data_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path() returns the expected path.
 */
TEST(config_data_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/protobuf/config_data",
	          config_data_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns non-nullptr
 */
TEST(config_data_rest_request_handler_test, create)
{
	std::unique_ptr<config_data_rest_request_handler> handler(
			config_data_rest_request_handler::create());

	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that the config_data_rest_request_handler is initially nullptr.
 */
TEST(config_data_rest_request_handler_test, config_data_message_handler_initially_nullptr)
{
	ASSERT_EQ(nullptr,
	          config_data_rest_request_handler::get_config_data_message_handler());
}

/**
 * Ensure that if set set the config data message handler,
 * get_config_data_message_handler() returns what we set.
 */
TEST(config_data_rest_request_handler_test, config_data_message_handler_set_get)
{
	scoped_config_data_rest_request_message_handler scoped_handler;

	std::shared_ptr<dummy_config_data_message_handler> message_handler =
		std::make_shared<dummy_config_data_message_handler>();
	config_data_rest_request_handler::set_config_data_message_handler(message_handler);

	ASSERT_EQ(message_handler,
	          config_data_rest_request_handler::get_config_data_message_handler());
}

/**
 * Ensure that if the REST handler doesn't have a registered data message
 * handler, a request to push new config fails.
 */
TEST(config_data_rest_request_handler_test, no_registered_data_message_handler)
{
	const std::string body = 
		R"EOF({"config_files":[{"name":"dragent.auto.yaml","content":"this:\n  that: true"}]})EOF";
	const std::string expected_response = R"EOF({
   "error" : "No config data message handler registered"
}
)EOF";
	const std::string path = config_data_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR;

	dummy_server_request request(path, body);
	dummy_server_response response;
	config_data_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	const std::string response_str = response.m_stream.str();
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response_str);
}

/**
 * Ensure that if the REST handler cannot parse the json in the request
 * document, it sends the expected response.
 */
TEST(config_data_rest_request_handler_test, cannot_parse_request_json)
{
	scoped_config_data_rest_request_message_handler scoped_handler;
	const std::string body = "{ this is not json }";
	const std::string expected_response = R"EOF({
   "error" : "Failed to parse config data json: Expected : between key:value pair.\n{ this is not json }\n       ^"
}
)EOF";
	std::shared_ptr<dummy_config_data_message_handler> message_handler =
		std::make_shared<dummy_config_data_message_handler>();

	const std::string path = config_data_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR;

	dummy_server_request request(path, body);
	dummy_server_response response;
	config_data_rest_request_handler handler;

	request.setMethod(method);

	config_data_rest_request_handler::set_config_data_message_handler(message_handler);
	handler.handleRequest(request, response);

	const std::string response_str = response.m_stream.str();
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response_str);
}

/**
 * Ensure that if the assocaited config_data_message_handler doesn't
 * accept the config, the config_data_rest_request_handler returns an
 * appropriate error.
 */
TEST(config_data_rest_request_handler_test, config_not_accepted)
{
	scoped_config_data_rest_request_message_handler scoped_handler;
	const std::string body = 
		R"EOF({"config_files":[{"name":"dragent.auto.yaml","content":"this:\n  that: true"}]})EOF";
	const std::string expected_response = R"EOF({
   "error" : "Configuration data not accepted"
}
)EOF";
	const bool accept_config = false;
	std::shared_ptr<dummy_config_data_message_handler> message_handler =
		std::make_shared<dummy_config_data_message_handler>(accept_config);
	const std::string path = config_data_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR;

	dummy_server_request request(path, body);
	dummy_server_response response;
	config_data_rest_request_handler handler;

	request.setMethod(method);

	config_data_rest_request_handler::set_config_data_message_handler(message_handler);
	handler.handleRequest(request, response);

	const std::string response_str = response.m_stream.str();
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response_str);
}

/**
 * Ensure that if the assocaited config_data_message_handler accepst the config,
 * the config_data_rest_request_handler returns the expected response.
 */
TEST(config_data_rest_request_handler_test, config_accepted)
{
	scoped_config_data_rest_request_message_handler scoped_handler;
	const std::string body = 
		R"EOF({"config_files":[{"name":"dragent.auto.yaml","content":"this:\n  that: true"}]})EOF";
	std::shared_ptr<dummy_config_data_message_handler> message_handler =
		std::make_shared<dummy_config_data_message_handler>();
	const std::string path = config_data_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_PUT;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;;

	dummy_server_request request(path, body);
	dummy_server_response response;
	config_data_rest_request_handler handler;

	request.setMethod(method);

	config_data_rest_request_handler::set_config_data_message_handler(message_handler);
	handler.handleRequest(request, response);

	const std::string response_str = response.m_stream.str();
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(body, response_str);
}
