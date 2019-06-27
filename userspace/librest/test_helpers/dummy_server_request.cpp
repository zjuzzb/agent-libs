/**
 * @file
 *
 * Implementation of dummy_server_request.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "dummy_server_request.h"
#include <stdexcept>
#include <string>

namespace test_helpers
{

dummy_server_request::dummy_server_request(const std::string& uri,
                                           const std::string& body)
{
	setURI(uri);

	if(!body.empty())
	{
		m_stream << body;
	}
}

std::istream& dummy_server_request::stream()
{
	return m_stream;
}

const Poco::Net::SocketAddress& dummy_server_request::clientAddress() const
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

const Poco::Net::SocketAddress& dummy_server_request::serverAddress() const
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

const Poco::Net::HTTPServerParams& dummy_server_request::serverParams() const
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

Poco::Net::HTTPServerResponse& dummy_server_request::response() const
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

bool dummy_server_request::secure() const
{
	throw std::runtime_error(std::string(__PRETTY_FUNCTION__) +
				 " not supported");
}

} // end namespace test_helpers
