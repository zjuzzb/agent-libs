/**
 * @file
 *
 * Interface to dummy_server_response.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include <Poco/Net/HTTPServerResponse.h>
#include <sstream>
#include <string>

namespace test_helpers
{

/**
 * A dummy realization of the HTTPServerResponse with which to test the
 * rest_request_handler.
 */
class dummy_server_response : public Poco::Net::HTTPServerResponse
{
public:
	/** Throws std::runtime_error. */
	void redirect(const std::string& uri,
	              Poco::Net::HTTPResponse::HTTPStatus status) override;

	/** Throws std::runtime_error. */
	void requireAuthentication(const std::string& realm) override;

	/** Returns m_stream. */
	std::ostream& send() override;

	/** Throws std::runtime_error. */
	void sendBuffer(const void* p_buffer, std::size_t length) override;

	/** Throws std::runtime_error. */
	void sendContinue() override;

	/** Throws std::runtime_error. */
	void sendFile(const std::string& path,
	              const std::string& media_type) override;

	/** Returns true. */
	bool sent() const override;

	/**
	 * Buffer into which the server response is written.
	 *
	 * @see send().
	 */
	std::stringstream m_stream;
};

} // end namespace test_helpers
