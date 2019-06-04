/**
 * @file
 *
 * Unit tests for dummy_server_response
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dummy_server_response.h"
#include <gtest.h>

using test_helpers::dummy_server_response;

/**
 * Ensure that redirect() throws a std::runtime_error.
 */
TEST(dummy_server_response_test, redirect_throws_runtime_error)
{
	const std::string uri = "/foo";
	const Poco::Net::HTTPResponse::HTTPStatus status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	dummy_server_response response;

	ASSERT_THROW(response.redirect(uri, status), std::runtime_error);
}

/**
 * Ensure that requireAuthentication() throws a std::runtime_error.
 */
TEST(dummy_server_response_test, requireAuthentication_throws_runtime_error)
{
	const std::string realm = "my_realm";
	dummy_server_response response;

	ASSERT_THROW(response.requireAuthentication(realm), std::runtime_error);
}

/**
 * Ensure that send() does not throw an exception.  Ensure that it returns
 * a reference to its stream.
 */
TEST(dummy_server_response_test, send_does_not_throw_any_exception)
{
	std::ostream* stream;
	dummy_server_response response;

	ASSERT_NO_THROW(stream = &response.send());
	ASSERT_EQ(&response.m_stream, stream);
}

/**
 * Ensure that sendBuffer() throws a std::runtime_error.
 */
TEST(dummy_server_response_test, sendBuffer_throws_runtime_error)
{
	char buffer[1];
	dummy_server_response response;

	ASSERT_THROW(response.sendBuffer(buffer, sizeof(buffer)), std::runtime_error);
}

/**
 * Ensure that sendContinue() throws a std::runtime_error.
 */
TEST(dummy_server_response_test, sendContinue_throws_runtime_error)
{
	dummy_server_response response;

	ASSERT_THROW(response.sendContinue(), std::runtime_error);
}

/**
 * Ensure that sendFile() throws a std::runtime_error.
 */
TEST(dummy_server_response_test, sendFile_throws_runtime_error)
{
	const std::string path = "/foo";
	const std::string media_type = "application/jpeg";
	dummy_server_response response;

	ASSERT_THROW(response.sendFile(path, media_type), std::runtime_error);
}

/**
 * Ensure that sent() does not throw an exception, and that it returns true.
 */
TEST(dummy_server_response_test, sent_returns_true)
{
	dummy_server_response response;
	bool sent = false;

	ASSERT_NO_THROW(sent = response.sent());
	ASSERT_EQ(true, sent);
}
