/**
 * @file
 *
 * Implementation of webpage_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "webpage_rest_request_handler.h"
#include "config_data_message_handler.h"
#include "draios.pb.h"
#include "webpage.h"
#include <streambuf>
#include <string>
#include <google/protobuf/io/gzip_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/util/json_util.h>
#include <json/json.h>

namespace dragent
{

webpage_rest_request_handler::webpage_rest_request_handler() :
   librest::rest_request_handler(get_path(),
				 "Webpage Rest Request Handler",
				 "Handles webpage")
{ }

std::string webpage_rest_request_handler::handle_get_request(
   Poco::Net::HTTPServerRequest& request,
   Poco::Net::HTTPServerResponse& response)
{
	std::string webpage = webpage::generate();

	response.setContentType("text/html");
	return webpage;
}

std::string webpage_rest_request_handler::get_path()
{
	return "/";
}

std::string webpage_rest_request_handler::get_versioned_path()
{
	// This isn't really needed but do this until there is a way
	// to leave the versioned path empty
	return "/v0";
}

webpage_rest_request_handler* webpage_rest_request_handler::create()
{
	return new webpage_rest_request_handler();
}

} // namespace dragent
