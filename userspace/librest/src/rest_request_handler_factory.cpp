/**
 * @file
 *
 * Implementation of rest_request_handler_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_request_handler.h"
#include "rest_request_handler_factory.h"
#include <assert.h>
#include <string>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>

namespace
{

/**
 * Return a 404 error indicating that the requested URI is not found.
 */
class not_found_request_handler : public Poco::Net::HTTPRequestHandler
{
public:
	void handleRequest(Poco::Net::HTTPServerRequest& request,
	                   Poco::Net::HTTPServerResponse& response) override
	{

		response.setContentType("application/json");
		response.setStatusAndReason(Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND);
		response.send() << "{ \"error\": \"Not found: " << request.getURI() << "\" }";
	}

	static not_found_request_handler* create()
	{
		return new not_found_request_handler();
	}
};

} // end namespace

namespace librest
{

Poco::Net::HTTPRequestHandler* rest_request_handler_factory::createRequestHandler(
		const Poco::Net::HTTPServerRequest& request)
{
	path_handler_factory factory_fn = lookup(request.getURI());

	return factory_fn();
}

void rest_request_handler_factory::register_path_handler(const std::string& path,
                                                         path_handler_factory handler)
{
	assert(m_handler_map.find(path) == m_handler_map.end());
	m_handler_map[path] = handler;
}

rest_request_handler_factory::path_handler_factory rest_request_handler_factory::lookup(
		const std::string& path) const
{
	// Default to a handler that returns 404 for all requests
	std::string pattern = path;

	while(!pattern.empty())
	{
		auto it = m_handler_map.find(pattern);

		if(it != m_handler_map.end())
		{
			return it->second;
		}
		else
		{
			const std::size_t last_slash = pattern.rfind("/");

			if(last_slash == std::string::npos)
			{
				break;
			}

			pattern = pattern.substr(0, last_slash);
		}
	}

	return not_found_request_handler::create;
}

} // end namespace librest
