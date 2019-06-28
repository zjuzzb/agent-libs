/**
 * @file
 *
 * Interface to fault_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#if defined(FAULT_INJECTION_ENABLED)

#include "rest_request_handler.h"

namespace dragent
{

/**
 * Request handler to view/modify an individual fault injection point.  The URI
 * is in the form:
 *
 * <pre>/api/v0/fault_injection/&lt;fault-name&gt;</pre>
 * or
 * <pre>/api/fault_injection/&lt;fault-name&gt;</pre>
 */
class fault_rest_request_handler : public librest::rest_request_handler
{
public:
	fault_rest_request_handler();

	/** Returns the unversioned path that this handles. */
	static std::string get_path();

	/** Returns the versioned path that this handles. */
	static std::string get_versioned_path();

	/** Factory method for creating new instances. */
	static fault_rest_request_handler* create();

protected:
	/**
	 * Handle HTTP GET request for the requested endpoint.
	 */
	std::string handle_get_request(Poco::Net::HTTPServerRequest&,
	                               Poco::Net::HTTPServerResponse&) override;
	std::string handle_put_request(Poco::Net::HTTPServerRequest&,
	                               Poco::Net::HTTPServerResponse&) override;
};

} // namespace dragent

#endif // defined(FAULT_INJECTION_ENABLED)
