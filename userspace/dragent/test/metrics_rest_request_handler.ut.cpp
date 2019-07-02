/**
 * @file
 *
 * Unit tests for metrics_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "draios.pb.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include "fault_handler.h"
#include "metrics_rest_request_handler.h"
#include "metric_store.h"
#include "scoped_fault.h"
#include "scoped_metric_store.h"
#include <google/protobuf/util/json_util.h>
#include <gtest.h>

using userspace_shared::fault_handler;
using test_helpers::dummy_server_request;
using test_helpers::dummy_server_response;
using test_helpers::scoped_fault;
using test_helpers::scoped_metric_store;

using namespace dragent;

/**
 * Ensure that get_path() returns the expected path.
 */
TEST(metrics_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/protobuf/metrics",
	          metrics_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path returns the expected path.
 */
TEST(metrics_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/protobuf/metrics",
	          metrics_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns a non-null pointer.
 */
TEST(metrics_rest_request_handler_test, create)
{
	std::shared_ptr<metrics_rest_request_handler> handler(
			metrics_rest_request_handler::create());
	ASSERT_NE(nullptr, handler.get());
}

/**
 * Ensure that when there are no metrics, the handler returns HTTP 404 and
 * a meaningful error message.
 */
TEST(metrics_rest_request_handler_test, no_metrics_returns_404)
{
	scoped_metric_store scoped_store;
	const std::string path = metrics_rest_request_handler::get_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	const std::string expected_response = R"EOF({
   "error" : "No metrics have been generated"
}
)EOF";

	libsanalyzer::metric_store::store(nullptr);

	dummy_server_request request(path);
	dummy_server_response response;
	metrics_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}

/**
 * Make sure that a request for the metrics protobuf returns the expected
 * JSON document.
 */
TEST(metrics_rest_request_handler_test, nonnull_metrics_returns_metrics)
{
	scoped_metric_store scoped_store;

	const std::string path = metrics_rest_request_handler::get_versioned_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

	std::shared_ptr<draiosproto::metrics> metrics =
		std::make_shared<draiosproto::metrics>();

	metrics->mutable_hostinfo()->set_hostname("my_hostname");

	libsanalyzer::metric_store::store(metrics);

	dummy_server_request request(path);
	dummy_server_response response;
	metrics_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(R"EOF({"hostinfo":{"hostname":"my_hostname"}})EOF",
	          response.m_stream.str());
}

/**
 * Ensure that if we fail to convert the metrics protobuf to JSON, the
 * metrics_rest_request_handler fails with an appropriate status and error
 * message.
 */
TEST(metrics_rest_request_handler_test, message_to_json_failure)
{
	scoped_fault fault("agent.userspace.dragent.metrics_rest_request_handler.message_to_json_error");

	fault.handler()->set_fault_mode(fault_handler::fault_mode::ALWAYS);
	fault.handler()->set_enabled(true);

	const std::string path = metrics_rest_request_handler::get_versioned_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR;
	const std::string expected_response = R"EOF({
   "error" : "MessageToJsonString error: ''"
}
)EOF";



	std::shared_ptr<draiosproto::metrics> metrics =
		std::make_shared<draiosproto::metrics>();

	metrics->mutable_hostinfo()->set_hostname("my_hostname");

	libsanalyzer::metric_store::store(metrics);

	dummy_server_request request(path);
	dummy_server_response response;
	metrics_rest_request_handler handler;

	request.setMethod(method);

	handler.handleRequest(request, response);

	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(expected_response, response.m_stream.str());
}
