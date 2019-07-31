/**
 * @file
 *
 * Implementation of file_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "file_rest_request_handler.h"
#include "webpage.h"
#include <common_logger.h>
#include <rest_exception.h>
#include <rest_util.h>
#include <string>
#include <Poco/Net/HTTPResponse.h>
#include <json/json.h>

COMMON_LOGGER();

namespace dragent
{

file_rest_request_handler::file_rest_request_handler(const file_rest_registry::file_list& paths) :
   librest::rest_request_handler(get_path(),
				 "file Rest Request Handler",
				 "Handles file requests"),
   m_files(paths)
{ }

std::string file_rest_request_handler::handle_get_request(
   Poco::Net::HTTPServerRequest& request,
   Poco::Net::HTTPServerResponse& response)
{
	const std::string file_name = librest::post_last_slash(request.getURI());

	if (file_name.empty())
	{
		THROW_REST_ERROR(Poco::Net::HTTPResponse::HTTPStatus::HTTP_BAD_REQUEST,
				 "Empty file not allowed");
	}

	std::string content = m_files.get_content_as_string(file_name);

	response.setContentType("text/plain");
	return content;
}

std::string file_rest_request_handler::get_path()
{
	return "/api/file";
}

std::string file_rest_request_handler::get_versioned_path()
{
	return "/api/v0/file";
}

file_rest_request_handler* file_rest_request_handler::create()
{
	return new file_rest_request_handler();
}

} // namespace dragent


