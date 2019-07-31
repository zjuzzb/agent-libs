/**
 * @file
 *
 * Interface to file_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include "file_rest_registry.h"
#include "rest_request_handler.h"

class connection_manager;

namespace dragent
{

/**
 * Request handler to handle files. The filename is passed as part of the
 * URI.
 */
class file_rest_request_handler : public librest::rest_request_handler
{
public:
	/**
	 * This has a way to provide a list of files for testing. In production, the
	 * empty set is used and the underlying file_registry has a default list of
	 * files.
	 */
	file_rest_request_handler(const file_rest_registry::file_list& paths = {});

	/** Returns the unversioned path that this handles. */
	static std::string get_path();

	/** Returns the versioned path that this handles. */
	static std::string get_versioned_path();

	/** Factory method for creating new instances. */
	static file_rest_request_handler* create();

protected:
	/**
	 * Handle HTTP GET request for the requested endpoint.
	 */
	std::string handle_get_request(Poco::Net::HTTPServerRequest&,
				       Poco::Net::HTTPServerResponse&) override;

private:
	file_rest_registry m_files;
};

} // namespace dragent
