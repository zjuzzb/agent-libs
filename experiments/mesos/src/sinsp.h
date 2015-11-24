#pragma once

#include <iostream>
#include <string>
#include <cassert>
#include <exception>
#include "Poco/Format.h"

struct sinsp_logger
{
	enum severity
	{
		SEV_DEBUG,
		SEV_INFO,
		SEV_WARNING,
		SEV_ERROR,
		SEV_CRITICAL
	};

	void log(const std::string& msg, sinsp_logger::severity sev = SEV_DEBUG)
	{

		std::cout << sev << ':' << msg << std::endl;
	}
};

extern sinsp_logger g_logger;

#ifdef _DEBUG
#define ASSERT(X) \
	if(!(X)) \
	{ \
		g_logger.log(Poco::format("ASSERTION %s at %s:%d", std::string(#X), std::string(__FILE__), __LINE__), sinsp_logger::SEV_ERROR); \
		assert(X); \
	} 
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

struct sinsp_exception : std::exception
{
	sinsp_exception()
	{
	}

	~sinsp_exception() throw()
	{
	}

	sinsp_exception(std::string error_str)
	{
		m_error_str = error_str;
	}

	char const* what() const throw()
	{
		return m_error_str.c_str();
	}

	std::string m_error_str;
};

