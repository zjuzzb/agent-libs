/**
 * @file
 *
 * Implementation of metrics_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "metrics_rest_request_handler.h"
#include "draios.pb.h"
#include "fault_injection.h"
#include "metric_store.h"
#include <google/protobuf/util/json_util.h>
#include <json/json.h>

namespace
{

DEFINE_FAULT_INJECTOR(
	fh_message_to_json_error,
	"agent.userspace.dragent.metrics_rest_request_handler.message_to_json_error",
	"Simulate a failure in MessageToJsonString()");

} // end namespace

namespace dragent
{

metrics_rest_request_handler::metrics_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Metrics Protobuf Rest Request Handler",
	                              "Handles REST request to get the latest "
	                              "metrics protobuf")
{ }

std::string metrics_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest&,
		Poco::Net::HTTPServerResponse& response)
{
	Json::Value value;
	Poco::Net::HTTPResponse::HTTPStatus http_status =
		Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;
	const std::shared_ptr<const draiosproto::metrics> metrics =
		libsanalyzer::metric_store::get();

	if(metrics != nullptr)
	{
		using ::google::protobuf::util::Status;

		std::string json_string;

		Status status =
			::google::protobuf::util::MessageToJsonString(*metrics,
			                                              &json_string);

		FAULT_FIRED_INVOKE(fh_message_to_json_error,
				   ([&status]() { status = Status::UNKNOWN; }));

		if(status.ok())
		{
			return json_string;
		}

		value["error"] = "MessageToJsonString error: '" +
		                 status.error_message().ToString() + "'";
		http_status = Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR;
	}
	else
	{
		value["error"] = "No metrics have been generated";
		http_status = Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND;
	}

	response.setStatusAndReason(http_status);
	return value.toStyledString();
}

std::string metrics_rest_request_handler::get_path()
{
	return "/api/protobuf/metrics";
}

std::string metrics_rest_request_handler::get_versioned_path()
{
	return "/api/v0/protobuf/metrics";
}

metrics_rest_request_handler* metrics_rest_request_handler::create()
{
	return new metrics_rest_request_handler();
}


} // namespace dragent
