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

std::string get_config_name(const std::string& uri)
{
	const std::size_t last_slash = uri.rfind("/");
	std::string fault_name;

	if(last_slash != std::string::npos)
	{
		fault_name = uri.substr(last_slash + 1);
	}

	return fault_name;
}

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
	const std::string config_name = get_config_name(request.getURI());

	if(config_name.empty())
	{
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
		return generate_json_error("Configuration option name not found");
	}

	const configuration_unit* const config =
		configuration_manager::instance().get_configuration_unit(config_name);

	if(config == nullptr)
	{
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND);
		return generate_json_error("Configuration option '" +
					   config_name +
					   "' not found");
	}

	return config->to_json();
}

std::string config_rest_request_handler::handle_put_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	Json::Value error_value;
	const std::string config_name = get_config_name(request.getURI());

	if(config_name.empty())
	{
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
		return generate_json_error("Configuration option name not found");
	}

	configuration_unit* const config =
		configuration_manager::instance().get_mutable_configuration_unit(config_name);

	if(config == nullptr)
	{
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND);
		error_value["error"] = "Configuration option '" +
				 config_name +
				 "' not found";
		return error_value.toStyledString();
	}

	try
	{
		// Read the body of the request
		const std::string body(std::istreambuf_iterator<char>(request.stream()),
				       std::istreambuf_iterator<char>());

		config->from_json(body);

		return config->to_json();
	}
	catch(const configuration_unit::exception& ex)
	{
		error_value["error"] = ex.what();
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);
		return error_value.toStyledString();
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
