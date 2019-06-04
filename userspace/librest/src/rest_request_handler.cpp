/**
 * @file
 *
 * Implementation of rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_request_handler.h"
#include "rest_exception.h"

namespace
{

/**
 * Throw a rest_exception indicating that the operation is not implemented.
 */
std::string default_response(const Poco::Net::HTTPServerRequest& request)
{
	using Poco::Net::HTTPResponse;

	throw librest::rest_exception(
		request.getMethod() + " not implemented",
		HTTPResponse::HTTPStatus::HTTP_NOT_IMPLEMENTED);
}

} // namespace

namespace librest
{

rest_request_handler::rest_request_handler(
		const std::string& path,
		const std::string& name,
		const std::string& description):
	m_path(path),
	m_name(name),
	m_description(description)
{ }

void rest_request_handler::handleRequest(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	using Poco::Net::HTTPRequest;
	using Poco::Net::HTTPResponse;

	try
	{
		std::string response_str;

		// Set a default response; subclasses can override this value.
		response.setContentType("application/json");

		if(request.getMethod() == HTTPRequest::HTTP_GET)
		{
			response_str = handle_get_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_PUT)
		{
			response_str = handle_put_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_POST)
		{
			response_str = handle_post_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_DELETE)
		{
			response_str = handle_delete_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_OPTIONS)
		{
			response_str = handle_options_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_PATCH)
		{
			response_str = handle_patch_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_CONNECT)
		{
			response_str = handle_connect_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_HEAD)
		{
			response_str = handle_head_request(request, response);
		}
		else if(request.getMethod() == HTTPRequest::HTTP_TRACE)
		{
			response_str = handle_trace_request(request, response);
		}
		else
		{
			response_str = handle_custom_request(request, response);
		}

		response.setStatusAndReason(HTTPResponse::HTTPStatus::HTTP_OK);
		response.send() << response_str;

		request_complete(request);
	}
	catch(const rest_exception& ex)
	{
		response.setStatusAndReason(static_cast<HTTPResponse::HTTPStatus>(ex.get_code()));
		response.send() << "{ \"error\": \"" << ex.what() << "\" }";
	}
}

std::string rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_put_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_post_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_patch_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_delete_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_options_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_connect_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_head_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_trace_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

std::string rest_request_handler::handle_custom_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse&)
{
	return default_response(request);
}

void rest_request_handler::request_complete(Poco::Net::HTTPServerRequest&)
{
	// Do nothing by default
}

const std::string& rest_request_handler::get_path() const
{
	return m_path;
}

const std::string& rest_request_handler::get_name() const
{
	return m_name;
}

const std::string& rest_request_handler::get_description() const
{
	return m_description;
}

} // namespace librest
