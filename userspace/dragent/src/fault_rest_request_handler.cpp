/**
 * @file
 *
 * Implementation of fault_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "fault_rest_request_handler.h"
#include "fault_handler_registry.h"
#include "fault_handler.h"
#include <streambuf>
#include <json/json.h>

using userspace_shared::fault_handler;
using userspace_shared::fault_handler_registry;

namespace
{

/**
 * Get what should be the fault name.  Specifically, this returns everything
 * after the last slash in the URI.  So something like:
 *
 * "/api/fault_injection/bob" will return "bob".
 *
 * If, for instance, the URI is:
 *
 * "/api/fault_injection", this will return "fault_injection".
 *
 * (i.e., this function does not make special considerations for the
 * registered fault path.)
 */
std::string get_fault_name(const std::string& uri)
{
	const std::size_t last_slash = uri.rfind("/");
	std::string fault_name;

	if(last_slash != std::string::npos)
	{
		fault_name = uri.substr(last_slash + 1);
	}

	return fault_name;
}

std::string bad_request(Poco::Net::HTTPServerResponse& response,
                        const std::string& message)
{
	Json::Value error_value;

	error_value["error"] = message;
	response.setStatusAndReason(
			Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);

	return error_value.toStyledString();
}

} // end namespace

namespace dragent
{

fault_rest_request_handler::fault_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Fault Injection Rest Request Handler",
	                              "Handles REST request to get/modify "
	                              "individual fault injection points")
{ }

std::string fault_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	Json::Value error_value;
	const std::string fault_name = get_fault_name(request.getURI());

	if(!fault_name.empty())
	{
		const fault_handler* const fault =
			fault_handler_registry::instance().find(fault_name);

		if(fault != nullptr)
		{
			return fault->to_json();
		}
		else
		{
			response.setStatusAndReason(
					Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND);
			error_value["error"] = "Fault injection point '" +
			                 fault_name +
			                 "' not found";
		}
	}
	else
	{
		return bad_request(response,
		                   "Fault injection point name not found in URL");
	}

	return error_value.toStyledString();
}

std::string fault_rest_request_handler::handle_put_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	Json::Value error_value;
	const std::string fault_name = get_fault_name(request.getURI());

	if(fault_name.empty())
	{
		return bad_request(response,
		                   "Fault injection point name not found in URL");
	}

	fault_handler* const fault =
		fault_handler_registry::instance().find(fault_name);

	if(fault == nullptr)
	{
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND);
		error_value["error"] = "Fault injection point '" +
				 fault_name +
				 "' not found";
		return error_value.toStyledString();
	}

	try
	{
		// Read the body of the request
		const std::string body(std::istreambuf_iterator<char>(request.stream()),
				       std::istreambuf_iterator<char>());

		fault->from_json(body);

		return fault->to_json();
	}
	catch(const fault_handler::exception& ex)
	{
		error_value["error"] = ex.what();
		response.setStatusAndReason(
				Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST);

		return error_value.toStyledString();
	}
}

std::string fault_rest_request_handler::get_path()
{
	return "/api/fault_injection";
}

std::string fault_rest_request_handler::get_versioned_path()
{
	return "/api/v0/fault_injection";
}

fault_rest_request_handler* fault_rest_request_handler::create()
{
	return new fault_rest_request_handler();
}

} // namespace dragent
