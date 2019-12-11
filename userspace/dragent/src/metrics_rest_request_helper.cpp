#include "metrics_rest_request_helper.h"
#include "fault_injection.h"
#include "metric_store.h"
#include <json/json.h>
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPServerResponse.h"
#include <google/protobuf/util/json_util.h>

namespace
{

DEFINE_FAULT_INJECTOR(
    fh_message_to_json_error,
    "agent.userspace.dragent.metrics_rest_request_handler.message_to_json_error",
    "Simulate a failure in MessageToJsonString()");

} // end namespace

namespace rest_metrics
{
std::string metrics_fetcher_helper(Poco::Net::HTTPServerResponse& response,
                                   const std::shared_ptr<const draiosproto::metrics> metrics)
{
    Json::Value value;
    Poco::Net::HTTPResponse::HTTPStatus http_status =
        Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK;

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
}
