/**
 * @file
 *
 * Implementation of faultlist_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

#include "faultlist_rest_request_handler.h"
#include "fault_handler_registry.h"

namespace dragent
{

faultlist_rest_request_handler::faultlist_rest_request_handler():
	librest::rest_request_handler(get_path(),
	                              "Fault Injection Point List Rest Request Handler",
	                              "Handles REST request to get a list of  "
	                              "all fault injection points")
{ }

std::string faultlist_rest_request_handler::handle_get_request(
		Poco::Net::HTTPServerRequest& request,
		Poco::Net::HTTPServerResponse& response)
{
	return userspace_shared::fault_handler_registry::instance().to_json();
}

std::string faultlist_rest_request_handler::get_path()
{
	return "/api/fault_injections";
}

std::string faultlist_rest_request_handler::get_versioned_path()
{
	return "/api/v0/fault_injections";
}

faultlist_rest_request_handler* faultlist_rest_request_handler::create()
{
	return new faultlist_rest_request_handler();
}


} // namespace dragent

#endif // defined(FAULT_INJECTION_ENABLED)
