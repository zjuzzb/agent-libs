/**
 * @file
 *
 * Interface to rest_request_handler_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <functional>
#include <map>
#include <string>
#include <Poco/Net/HTTPRequestHandlerFactory.h>

namespace Poco { namespace Net { class HTTPServerRequest; } }

namespace librest
{

/**
 * A factory for creating HTTPRequestHandler.  Clients of objects of this
 * type will use the provided register_path_handler() method to register
 * factory functions for URI path (or path prefixes).  When the
 * rest_request_handler_factory gets a request to build a HTTPRequestHandler
 * for a given URI, it will search for a registered path prefix match that
 * corresponds to the given URI.  If one is found, it will use the associated
 * factory function to create an return an instance of that type.  If no
 * registered path matches the given URI, then the rest_request_handler_factory
 * will return a HTTPRequestHandler that responds with HTTP status 404 for
 * all requests.
 */
class rest_request_handler_factory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
	using path_handler_factory = std::function<Poco::Net::HTTPRequestHandler*(void)>;

	/**
	 * Create a new HTTPRequestHandler based on the given request.
	 */
	Poco::Net::HTTPRequestHandler* createRequestHandler(
		 const Poco::Net::HTTPServerRequest& request) override;

	/**
	 * Register a factory function that will create HTTPRequestHandler
	 * that respond to requests with the given path (or path prefix).
	 */
	void register_path_handler(const std::string& path,
	                           path_handler_factory handler);


	/**
	 * Convenience method to register a path handler based only on the
	 * type.
	 *
	 * @tparam handler_type The type of the path handler factory.  The
	 *                      expectation is that this type will expose
	 *                      three static method: get_path(),
	 *                      get_versioned_path(), and create().  get_path()
	 *                      will return the non-versioned path to register.
	 *                      get_versioned_path() will return the versioned
	 *                      path to register.  create() is the factory
	 *                      method that will be registered to create new
	 *                      instances.
	 */
	template<typename handler_type>
	void register_path_handler()
	{
		const std::string path = handler_type::get_path();

		if(!path.empty())
		{
			register_path_handler(path, handler_type::create);
		}

		const std::string versioned_path = handler_type::get_versioned_path();

		if(!versioned_path.empty())
		{
			register_path_handler(versioned_path,
			                      handler_type::create);
		}
	}

private:
	using path_handler_map = std::map<std::string, path_handler_factory>;

	/**
	 * Try to find a factory function that matches the given path (with
	 * the longest match).
	 */
	path_handler_factory lookup(const std::string& path) const;

	path_handler_map m_handler_map;
};

} // end namespace librest
