/**
 * @file
 *
 * Interface to dummy_server_request.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include <sstream>
#include <string>
#include <Poco/Net/HTTPServerRequest.h>

namespace test_helpers
{

/**
 * A dummy realization of the HTTPServerRequest with which to test the
 * rest_request_handler.
 */
class dummy_server_request : public Poco::Net::HTTPServerRequest
{
public:
	/**
	 * Creates a new dummy_server_request with the given URI
	 */
	dummy_server_request(const std::string& uri, const std::string& body = "");

	/** Returns m_stream */
	std::istream& stream() override;

	/** throws std::runtime_error. */
	const Poco::Net::SocketAddress& clientAddress() const override;

	/** throws std::runtime_error. */
	const Poco::Net::SocketAddress& serverAddress() const override;

	/** throws std::runtime_error. */
	const Poco::Net::HTTPServerParams& serverParams() const override;

	/** throws std::runtime_error. */
	Poco::Net::HTTPServerResponse& response() const override;

	/** throws std::runtime_error. */
	bool secure() const override;

	std::stringstream m_stream;
};

}
