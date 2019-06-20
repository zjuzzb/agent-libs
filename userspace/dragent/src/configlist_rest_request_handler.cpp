/**
 * @file
 *
 * Implementation of configlist_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "configlist_rest_request_handler.h"
#include "configuration_manager.h"
#include "type_config.h"

namespace dragent
{

configlist_rest_request_handler::configlist_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Configuraiton List Rest Request Handler",
	                              "Handles REST request to get a list of  "
	                              "all configuration values")
{ }

std::string configlist_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	return configuration_manager::instance().to_json();
}

std::string configlist_rest_request_handler::get_path()
{
	return "/api/configs";
}

std::string configlist_rest_request_handler::get_versioned_path()
{
	return "/api/v0/configs";
}

configlist_rest_request_handler* configlist_rest_request_handler::create()
{
	return new configlist_rest_request_handler();
}


} // namespace dragenlibrestt
