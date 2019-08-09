/**
 * @file
 *
 * Interface to config_data_rest_request_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include "rest_request_handler.h"
#include "connection_manager.h"

namespace dragent
{

/**
 * Request handler to inject a new config_data protobuf.  The URI is in the
 * form:
 *
 * <pre>/api/v0/protobuf/config_data
 * or
 * <pre>/api/protobuf/config_data
 */
class config_data_rest_request_handler : public librest::rest_request_handler
{
public:
	config_data_rest_request_handler();

	/** Returns the unversioned path that this handles. */
	static std::string get_path();

	/** Returns the versioned path that this handles. */
	static std::string get_versioned_path();

	/** Factory method for creating new instances. */
	static config_data_rest_request_handler* create();

	/**
	 * Set the config data message handler that will accept incoming
	 * requests to update the config data.
	 */
	static void set_config_data_message_handler(connection_manager::message_handler::ptr cm);

	/**
	 * Returns the currently registered config data message handler, or
	 * nullptr if non is currently registered.
	 */
	static connection_manager::message_handler::ptr get_config_data_message_handler();

protected:
	/**
	 * Handle HTTP GET request for the requested endpoint.
	 */
	std::string handle_put_request(Poco::Net::HTTPServerRequest&,
	                               Poco::Net::HTTPServerResponse&) override;

private:
	static connection_manager::message_handler::ptr s_config_data_message_handler;
};

} // namespace dragent
