/**
 * @file
 *
 * Interface to config_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include "rest_request_handler.h"

namespace dragent
{

/**
 * Request handler to return an individual config value.  The URI is in the
 * form:
 *
 * <pre>/api/v0/config/&lt;config-name&gt;</pre>
 * or
 * <pre>/api/config/&lt;config-name&gt;</pre>
 */
class config_rest_request_handler : public librest::rest_request_handler
{
public:
	config_rest_request_handler();

	/** Returns the unversioned path that this handles. */
	static std::string get_path();

	/** Returns the versioned path that this handles. */
	static std::string get_versioned_path();

	/** Factory method for creating new instances. */
	static config_rest_request_handler* create();

protected:
	/**
	 * Handle HTTP GET request for the requested endpoint.
	 */
	std::string handle_get_request(Poco::Net::HTTPServerRequest&,
	                               Poco::Net::HTTPServerResponse&) override;
};

} // namespace dragent
