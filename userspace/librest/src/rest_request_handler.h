/**
 * @file
 *
 * Interface to rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>

namespace librest
{

/**
 * Base class for objects that can response to REST API requests.  This, by
 * default, responds with "not implemented" for all request.  Developers
 * should subclass this and override the handle_XXX_request methods that they
 * wish to handle.
 */
class rest_request_handler : public Poco::Net::HTTPRequestHandler
{
public:
	/**
	 * Initialize this rest_request_handler.  Request handlers are based
	 * on the URL path of the request HTTP request.
	 *
	 * @param[in] path        The path prefix that this rest_request_handler
	 *                        handles.
	 * @param[in] name        The name of this handler.
	 * @param[in] description The description of this handler.
	 */
	rest_request_handler(const std::string& path,
	                     const std::string& name,
	                     const std::string& description);

	// Prevent copy and assignment
	rest_request_handler(const rest_request_handler&) = delete;
	rest_request_handler(rest_request_handler&&) = delete;
	rest_request_handler& operator=(const rest_request_handler&) = delete;
	rest_request_handler& operator=(rest_request_handler&&) = delete;

	/**
	 * Handles an incoming HTTP request to the REST API.  This dispatches
	 * the the protected methods below.
	 */
	void handleRequest(Poco::Net::HTTPServerRequest& request,
	                   Poco::Net::HTTPServerResponse& response) override;

	/** @returns the path for this handler. */
	const std::string& get_path() const;

	/** @returns the name of this handler. */
	const std::string& get_name() const;

	/** @returns the description of this handler. */
	const std::string& get_description() const;

protected:
	/**
	 * Handles HTTP GET request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_get_request(Poco::Net::HTTPServerRequest&,
	                                       Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP PUT request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_put_request(Poco::Net::HTTPServerRequest&,
	                                       Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP POST request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_post_request(Poco::Net::HTTPServerRequest&,
	                                        Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP PATCH request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_patch_request(Poco::Net::HTTPServerRequest&,
	                                        Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP DELETE request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_delete_request(Poco::Net::HTTPServerRequest&,
	                                          Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP OPTIONS request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_options_request(Poco::Net::HTTPServerRequest&,
	                                           Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP CONNECT request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_connect_request(Poco::Net::HTTPServerRequest&,
	                                           Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP HEAD request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_head_request(Poco::Net::HTTPServerRequest&,
	                                        Poco::Net::HTTPServerResponse&);
	/**
	 * Handles HTTP TRACE request. This throws a rest_exception;
	 * subclasses should override it if they wish with to handle this
	 * request.
	 */
	virtual std::string handle_trace_request(Poco::Net::HTTPServerRequest&,
	                                         Poco::Net::HTTPServerResponse&);
	/**
	 * Handles any non-standard HTTP request. This throws a
	 * rest_exception; subclasses should override it if they
	 * wish with to handle this request.
	 */
	virtual std::string handle_custom_request(Poco::Net::HTTPServerRequest&,
	                                         Poco::Net::HTTPServerResponse&);

	/**
	 * Invoked after a successful call to handle_request.
	 */
	virtual void request_complete(Poco::Net::HTTPServerRequest& request);

private:
	const std::string m_path;
	const std::string m_name;
	const std::string m_description;
};

} // end namespace librest
