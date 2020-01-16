/**
 * @file
 *
 * Implementation of metrics_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "post_aggregated_metrics_rest_request_handler.h"
#include "metrics_rest_request_helper.h"
#include "metric_store.h"
#include <google/protobuf/util/json_util.h>
#include <json/json.h>

namespace dragent
{

post_aggregated_metrics_rest_request_handler::post_aggregated_metrics_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Metrics Protobuf Rest Request Handler",
	                              "Handles REST request to get the latest "
	                              "metrics protobuf")
{ }

std::string post_aggregated_metrics_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest&,
		Poco::Net::HTTPServerResponse& response)
{
	return rest_metrics::metrics_fetcher_helper(response, libsanalyzer::metric_store::get());
}

std::string post_aggregated_metrics_rest_request_handler::get_path()
{
	return "/api/protobuf/metrics";
}

std::string post_aggregated_metrics_rest_request_handler::get_versioned_path()
{
	return "/api/v0/protobuf/metrics";
}

post_aggregated_metrics_rest_request_handler* post_aggregated_metrics_rest_request_handler::create()
{
	return new post_aggregated_metrics_rest_request_handler();
}

} // namespace dragent
