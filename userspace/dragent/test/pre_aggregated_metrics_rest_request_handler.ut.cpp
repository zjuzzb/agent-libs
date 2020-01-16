/**
 * @file
 *
 * Unit tests for post_aggregated_metrics_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "draios.pb.h"
#include "dummy_server_request.h"
#include "dummy_server_response.h"
#include "fault_handler.h"
#include "pre_aggregated_metrics_rest_request_handler.h"
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
TEST(pre_aggregated_metrics_rest_request_handler_test, get_path)
{
	ASSERT_EQ("/api/protobuf/preagg_metrics",
	          pre_aggregated_metrics_rest_request_handler::get_path());
}

/**
 * Ensure that get_versioned_path returns the expected path.
 */
TEST(pre_aggregated_metrics_rest_request_handler_test, get_versioned_path)
{
	ASSERT_EQ("/api/v0/protobuf/preagg_metrics",
	          pre_aggregated_metrics_rest_request_handler::get_versioned_path());
}

/**
 * Ensure that create() returns a non-null pointer.
 */
TEST(pre_aggregated_metrics_rest_request_handler_test, create)
{
	std::shared_ptr<pre_aggregated_metrics_rest_request_handler> handler(
			pre_aggregated_metrics_rest_request_handler::create());
	ASSERT_NE(nullptr, handler.get());
}

/**
 * Make sure that a request for the metrics protobuf returns the expected
 * JSON document.
 */
TEST(pre_aggregated_metrics_rest_request_handler_test, nonnull_metrics_returns_metrics)
{
	scoped_metric_store scoped_store;

	const std::string path = pre_aggregated_metrics_rest_request_handler::get_versioned_path();
	const std::string& method = Poco::Net::HTTPRequest::HTTP_GET;
	const Poco::Net::HTTPResponse::HTTPStatus expected_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

	std::shared_ptr<draiosproto::metrics> metrics =
		std::make_shared<draiosproto::metrics>();

	metrics->mutable_hostinfo()->set_hostname("my_hostname");

	libsanalyzer::metric_store::store_pre_aggregated(metrics);

	dummy_server_request request(path);
	dummy_server_response response;
	pre_aggregated_metrics_rest_request_handler handler;

	request.setMethod(method);

	ASSERT_NE(libsanalyzer::metric_store::get_pre_aggregated(), nullptr);
	handler.handleRequest(request, response);
	ASSERT_EQ(expected_status, response.getStatus());
	ASSERT_EQ(R"EOF({"hostinfo":{"hostname":"my_hostname"}})EOF",
	          response.m_stream.str());
}

// Note the test helper is tested through the post aggregation tests, so we don't bother to
// repeat them here
