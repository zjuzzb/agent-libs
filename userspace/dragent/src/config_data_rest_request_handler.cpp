/**
 * @file
 *
 * Implementation of config_data_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_data_rest_request_handler.h"
#include "draios.pb.h"
#include "config_data_message_handler.h"
#include "draios.pb.h"
#include <streambuf>
#include <string>
#include <google/protobuf/io/gzip_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/util/json_util.h>
#include <json/json.h>

namespace dragent
{

config_data_message_handler* config_data_rest_request_handler::s_config_data_message_handler = nullptr;

config_data_rest_request_handler::config_data_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "config_data Protobuf Rest Request Handler",
	                              "Handles REST request push new config data "
	                              "to the agent")
{ }

void config_data_rest_request_handler::set_config_data_message_handler(
		config_data_message_handler* const cm)
{
	s_config_data_message_handler = cm;
}

config_data_message_handler* config_data_rest_request_handler::get_config_data_message_handler()
{
	return s_config_data_message_handler;
}

std::string config_data_rest_request_handler::handle_put_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	Json::Value error_json;

	if(!s_config_data_message_handler)
	{
		error_json["error"] = "No config data message handler registered";
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR);
		return error_json.toStyledString();
	}

	// Read the body of the request
	const std::string body(std::istreambuf_iterator<char>(request.stream()),
	                       std::istreambuf_iterator<char>());

	// Convert the JSON to a protobuf
	draiosproto::config_data config_data;
	const ::google::protobuf::util::Status status =
		::google::protobuf::util::JsonStringToMessage(body,
							      &config_data);

	if(status.ok())
	{
		//
		// We have the config_data protobuf.  We need to convert it
		// into a gzipped byte stream since that's what the
		// config_data_message_handler expects.
		//
		std::string data;
		::google::protobuf::io::StringOutputStream stream(&data);
		::google::protobuf::io::GzipOutputStream gzstream(&stream);

		if(config_data.SerializeToZeroCopyStream(&gzstream))
		{
			gzstream.Close();

			if(s_config_data_message_handler->handle_config_data(
					reinterpret_cast<const uint8_t*>(data.data()),
					data.size()))
			{
				return body;
			}
			else
			{
				error_json["error"] = "Configuration data not accepted";
			}
		}
		else
		{
			error_json["error"] = "Failed to gzip protobuf";
		}
	}
	else
	{
		error_json["error"] = "Failed to parse config data json: " +
		                 status.error_message().ToString();
	}

	response.setStatusAndReason(
			Poco::Net::HTTPResponse::HTTPStatus::HTTP_INTERNAL_SERVER_ERROR);
	return error_json.toStyledString();
}

std::string config_data_rest_request_handler::get_path()
{
	return "/api/protobuf/config_data";
}

std::string config_data_rest_request_handler::get_versioned_path()
{
	return "/api/v0/protobuf/config_data";
}

config_data_rest_request_handler* config_data_rest_request_handler::create()
{
	return new config_data_rest_request_handler();
}

} // namespace dragent
