/**
 * @file
 *
 * Implementation of metrics_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "pre_aggregated_metrics_rest_request_handler.h"
#include "metric_store.h"
#include "metrics_rest_request_helper.h"
#include <google/protobuf/util/json_util.h>
#include <json/json.h>

namespace dragent
{

pre_aggregated_metrics_rest_request_handler::pre_aggregated_metrics_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Metrics Protobuf Rest Request Handler",
	                              "Handles REST request to get the latest "
	                              "metrics protobuf")
{ }

std::string pre_aggregated_metrics_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest&,
		Poco::Net::HTTPServerResponse& response)
{
	return rest_metrics::metrics_fetcher_helper(response, libsanalyzer::metric_store::get_pre_aggregated());
}

std::string pre_aggregated_metrics_rest_request_handler::get_path()
{
	return "/api/protobuf/preagg_metrics";
}

std::string pre_aggregated_metrics_rest_request_handler::get_versioned_path()
{
	return "/api/v0/protobuf/preagg_metrics";
}

pre_aggregated_metrics_rest_request_handler* pre_aggregated_metrics_rest_request_handler::create()
{
	return new pre_aggregated_metrics_rest_request_handler();
}

} // namespace dragent
