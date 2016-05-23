#pragma once

#include <iostream>
#include <string>
#include <cassert>
#include <exception>
#include "json/json.h"
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

inline std::string& trim(std::string& val)
{
	val.erase(val.begin(), find_if(val.begin(), val.end(), std::not1(std::ptr_fun<int, int>(isspace))));
	val.erase(find_if(val.rbegin(), val.rend(), std::not1(std::ptr_fun<int, int>(isspace))).base(), val.end());
	return val;
}

inline std::string get_json_string(const Json::Value& root, const std::string& name)
{
	std::string ret;
	Json::Value json_val = root[name];
	if(!json_val.isNull() && json_val.isString())
	{
		ret = json_val.asString();
	}
	return ret;
}

template<typename charT>
struct ci_equal
{
	ci_equal( const std::locale& loc ) : m_loc(loc) {}
	bool operator()(charT ch1, charT ch2)
	{
		return std::toupper(ch1, m_loc) == std::toupper(ch2, m_loc);
	}
private:
	const std::locale& m_loc;
};

template<typename T>
int ci_find_substr(const T& str1, const T& str2, const std::locale& loc = std::locale())
{
	typename T::const_iterator it = std::search( str1.begin(), str1.end(),
		str2.begin(), str2.end(), ci_equal<typename T::value_type>(loc) );
	if(it != str1.end()) { return it - str1.begin(); }
	return -1;
}

