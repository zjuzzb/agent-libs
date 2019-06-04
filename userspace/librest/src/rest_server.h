/**
 * @file
 *
 * Interface to rest_server.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>

namespace librest
{

/**
 * The rest_server uses an HTTPRequestHandlerFactory to create objects to handle
 * HTTP requests.  Generally, we use rest_request_handler_factory --- a
 * concrete realization of that interface -- to handle requests.  The
 * rest_request_handler_factory maintains a map from path to delegate request
 * handler.  This enables us to register different request handlers for
 * different paths.
 * <p/>
 * The general approach is:<br/>
 * <pre>
 *     Poco::SharedPtr<rest_request_handler_factory> factory(
 *                    new rest_request_handler_factory());
 *
 *     factory->register_path_handler("/foo", foo_handler_class::create);
 *     factory->register_path_handler("/bar", bar_handler_class::create);
 *     ...
 *
 *     s_rest_server = make_unique<librest::rest_server>(factory, tcp_port);
 *     s_rest_server->start(); 
 * </pre>
 *
 * In the example, foo_handler_class::create and bar_handler_class::create
 * are factory functions that return instances of foo_handler_class and
 * bar_handler_class, respectively.  When the rest_server receives a request
 * with a prefix of "/foo", then it uses the provided factory function to
 * create a handler, then passes the request off to the newly-created handler.
 * The same applies to a request with prefix "/bar".
 *
 * If a request is made for a path that has no registered handler, then the
 * rest_server will return 404.
 */
class rest_server
{
public:
	/**
	 * Special value for port parameter that indicates that the
	 * rest_server should select an ephemeral port.
	 */
	const static uint16_t SELECT_EPHEMERAL_PORT;

	/** Default address of the localhost. */
	const static std::string LOCALHOST;

	/**
	 * Initialize this rest_server listening on the given port with the
	 * given host.
	 *
	 * @param[in] handler_factory Factory for producing objects that handle
	 *                            REST API requests.  Must not be nullptr.
	 * @param[in] port            The port on which to listen.  If port is
	 *                            SELECT_EPHEMERAL_PORT, then the server
	 *                            will select an ephemeral port.
	 * @param[in] host            The host/address on which to listen.  This
	 *                            must be some address or host name
	 *                            associated with the network namespace in
	 *                            which this code is running.
	 */
	rest_server(Poco::Net::HTTPRequestHandlerFactory::Ptr handler_factory,
	            uint16_t port = SELECT_EPHEMERAL_PORT,
	            const std::string& host = LOCALHOST);

	/**
	 * Tear down this rest_server, stopping it if it's running.
	 */
	~rest_server();

	// Prevent copy and assignment
	rest_server(const rest_server&) = delete;
	rest_server(rest_server&&) = delete;
	rest_server& operator=(const rest_server&) = delete;
	rest_server& operator=(rest_server&&) = delete;

	/**
	 * Starts this rest_server if it is not already running.  If this
	 * rest_server is already running, this method does nothing.
	 */
	void start();

	/**
	 * Stops this rest_server if it is running.  If this rest_server is not
	 * running, this method does nothing.
	 */
	void stop();

	/**
	 * Returns true if this rest_server is running, false otherwise.  Note
	 * that this is here for UT visibility; it is subject to potential
	 * race conditions.  Do not try to build logic in production code
	 * around this method.
	 */
	bool is_running() const;

	/**
	 * Returns the port on which the server is listening.
	 */
	uint16_t get_port() const;

	/**
	 * Returns the host/address on which this server is listening.
	 */
	const std::string& get_host() const;

private:
	/**
	 * Entry point to an async thread that runs the server.
	 */
	void run();

	std::thread m_thread;
	mutable std::mutex m_mutex;
	std::condition_variable m_running_condition;
	std::condition_variable m_stopping_condition;
	bool m_running;

	const Poco::Net::HTTPRequestHandlerFactory::Ptr m_handler_factory;

	/** The local hostname or IP to which to bind. */
	const std::string m_host;

	/** The TCP port on which to listen. */
	const uint16_t m_port;

	std::unique_ptr<Poco::Net::HTTPServer> m_server;
};

} // end namespace librest
