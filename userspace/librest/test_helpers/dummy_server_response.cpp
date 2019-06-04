/**
 * @file
 *
 * Implmentation of dummy_server_response.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dummy_server_response.h"
#include <stdexcept>

namespace test_helpers
{

void dummy_server_response::redirect(const std::string& uri,
	      Poco::Net::HTTPResponse::HTTPStatus status)
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

void dummy_server_response::requireAuthentication(const std::string& realm)
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

std::ostream& dummy_server_response::send()
{
	return m_stream;
}

void dummy_server_response::sendBuffer(const void* p_buffer, std::size_t length)
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

void dummy_server_response::sendContinue()
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

void dummy_server_response::sendFile(const std::string& path,
	      const std::string& media_type)
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

bool dummy_server_response::sent() const
{
	return true;
}

} // end namespace test_helpers
