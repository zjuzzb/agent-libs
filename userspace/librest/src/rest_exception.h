/**
 * @file
 *
 * Interface to rest_exception.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once
#include <exception>
#include <string>

// Shorthand macro to log and throw a rest exception for with a particular
// error code. This is meant to be used with the common logger.
#define THROW_REST_ERROR(__code, __fmt, ...)                                   \
do {                                                                           \
	std::string c_err_ = s_log_sink.build(__fmt,                           \
					      ##__VA_ARGS__);                  \
	s_log_sink.log(Poco::Message::Priority::PRIO_ERROR,                    \
		       __LINE__,                                               \
		       "Throwing: " + c_err_);                                 \
	throw librest::rest_exception(c_err_.c_str(), __code);                 \
} while(false)

namespace librest
{

/**
 * An exception from the REST API framework.
 */
class rest_exception : public std::exception
{
public:
	/** Default code if no code is specified. */
	const static int DEFAULT_CODE;

	/**
	 * Initialize this rest_exception with the given message
	 * and HTTP status code.
	 *
	 * @param[in] message The message specified by the client.
	 * @param[in] code    The HTTP status code specified by the client.
	 */
	rest_exception(const std::string& message, int code = DEFAULT_CODE);

	/**
	 * @returns a C-string representation of the message provided by the
	 *          client.
	 */
	const char* what() const noexcept override;

	/**
	 * @returns the HTTP status code provided by the client
	 */
	int get_code() const;

private:
	const std::string m_message;
	const int m_code;
};

} // namespace librest
