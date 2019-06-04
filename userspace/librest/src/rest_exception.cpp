/**
 * @file
 *
 * Implementation of rest_exception.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_exception.h"

namespace librest
{

const int rest_exception::DEFAULT_CODE = 0;

rest_exception::rest_exception(const std::string& message, const int code):
	m_message(message),
	m_code(code)
{ }

const char*
rest_exception::what() const noexcept
{
	return m_message.c_str();
}

int
rest_exception::get_code() const
{
	return m_code;
}

} // namespace librest
