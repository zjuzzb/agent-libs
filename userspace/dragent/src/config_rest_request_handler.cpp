/**
 * @file
 *
 * Implementation of config_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_rest_request_handler.h"
#include "configuration_manager.h"
#include "type_config.h"
#include <json/json.h>

namespace
{

/**
 * Returns a JSON-formatted error with the given message.
 */
std::string generate_json_error(const std::string& msg)
{
	Json::Value value;

	value["error"] = msg;

	return value.toStyledString();
}

} // end namespace

namespace dragent
{

config_rest_request_handler::config_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Configuration Rest Request Handler",
	                              "Handles REST request to get/modify "
	                              "individual configuration values")
{ }

std::string config_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	const std::string uri = request.getURI();
	const std::size_t last_slash = uri.rfind("/");

	if(last_slash != std::string::npos)
	{
		const std::string config_name = uri.substr(last_slash + 1);
		const configuration_unit* const config =
			configuration_manager::instance().get_configuration_unit(config_name);

		if(config != nullptr)
		{
			return config->to_json();
		}
		else
		{
			response.setStatusAndReason(
					Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND);
			return generate_json_error("Configuration option '" +
			                           config_name +
			                           "' not found");
		}
	}
	else
	{
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
		return generate_json_error("Configuration option name not found");
	}
}

std::string config_rest_request_handler::get_path()
{
	return "/api/config";
}

std::string config_rest_request_handler::get_versioned_path()
{
	return "/api/v0/config";
}

config_rest_request_handler* config_rest_request_handler::create()
{
	return new config_rest_request_handler();
}

} // namespace dragent
