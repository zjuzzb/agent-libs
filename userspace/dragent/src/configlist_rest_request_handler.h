/**
 * @file
 *
 * Interface to configlist_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "rest_request_handler.h"

namespace dragent
{

/**
 * Request handler to return a list of all config objects.  The URI is in the
 * form:
 *
 * <pre>/api/v0/configs</pre>
 *
 * or
 *
 * <pre>/api/configs</pre>
 */
class configlist_rest_request_handler : public librest::rest_request_handler
{
public:
	configlist_rest_request_handler();

	/** Returns the unversioned path that this handles. */
	static std::string get_path();

	/** Returns the versioned path that this handles. */
	static std::string get_versioned_path();

	/** Factory method for creating new instances. */
	static configlist_rest_request_handler* create();

protected:
	std::string handle_get_request(Poco::Net::HTTPServerRequest&,
	                               Poco::Net::HTTPServerResponse&) override;
};

} // namespace dragent

