#pragma once

#include <iostream>
#include <string>
#include <cassert>
#include <exception>
#include <algorithm> 
#include "Poco/Format.h"
#include <strings.h>
#include <sys/time.h>
#include "json/json.h"

using namespace std;

struct sinsp_logger
{
	enum severity
	{
		SEV_FATAL = 1,
		SEV_CRITICAL = 2,
		SEV_ERROR = 3,
		SEV_WARNING = 4,
		SEV_NOTICE = 5,
		SEV_INFO = 6,
		SEV_DEBUG = 7,
		SEV_TRACE = 8,
		SEV_MIN = SEV_FATAL,
		SEV_MAX = SEV_TRACE
	};

	enum event_severity
	{
		SEV_EVT_EMERGENCY = 10,
		SEV_EVT_FATAL = 11,
		SEV_EVT_CRITICAL = 12,
		SEV_EVT_ERROR = 13,
		SEV_EVT_WARNING = 14,
		SEV_EVT_NOTICE = 15,
		SEV_EVT_INFORMATION = 16,
		SEV_EVT_DEBUG = 17,
		SEV_EVT_MIN = SEV_EVT_EMERGENCY,
		SEV_EVT_MAX = SEV_EVT_DEBUG
	};
	void log(const std::string& msg, severity sev = SEV_DEBUG)
	{
		std::cout << sev << ':' << msg << std::endl;
	}

	void log(std::string, event_severity)
	{
	}

	severity get_severity() const
	{
		return SEV_DEBUG;
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

struct ci_compare
{
	// less-than, for use in STL containers
	bool operator() (const std::string& a, const std::string& b) const
	{
#ifndef _WIN32
		return strcasecmp(a.c_str(), b.c_str()) < 0;
#else
		return lstrcmpiA(a.c_str(), b.c_str()) < 0;
#endif // _WIN32
	}

	static bool is_equal(const std::string& a, const std::string& b)
	{
#ifndef _WIN32
		return strcasecmp(a.c_str(), b.c_str()) == 0;
#else
		return lstrcmpiA(a.c_str(), b.c_str()) == 0;
#endif // _WIN32
	}
};

inline std::string get_json_string(const Json::Value& obj, const std::string& name)
{
	std::string ret;
	const Json::Value& json_val = obj[name];
	if(!json_val.isNull() && json_val.isConvertibleTo(Json::stringValue))
	{
		ret = json_val.asString();
	}
	return ret;
}

inline std::string json_as_string(const Json::Value& json)
{
	return Json::FastWriter().write(json);
}

inline time_t get_epoch_utc_seconds(const std::string& time_str, const std::string& fmt = "%Y-%m-%dT%H:%M:%SZ")
{
#ifndef _WIN32
	if(time_str.empty() || fmt.empty())
	{
		throw sinsp_exception("get_epoch_utc_seconds(): empty time or format string.");
	}
	struct tm tm_time = {0};
	strptime(time_str.c_str(), fmt.c_str(), &tm_time);
	tm_time.tm_isdst = -1; // strptime does not set this, signal timegm to determine DST
	return timegm(&tm_time);
#else
	throw sinsp_exception("get_epoch_utc_seconds() not implemented on Windows");
#endif // _WIN32
}

inline time_t get_epoch_utc_seconds_now()
{
#ifndef _WIN32
	time_t rawtime;
	time(&rawtime);
	return timegm(gmtime(&rawtime));
#else
	throw sinsp_exception("get_now_seconds() not implemented on Windows");
#endif // _WIN32
}

//
// trim from start
//
inline std::string& ltrim(std::string &s) 
{
	s.erase(s.begin(), find_if(s.begin(), s.end(), not1(ptr_fun<int, int>(isspace))));
	return s;
}

//
// trim from end
//
inline std::string& rtrim(std::string &s) 
{
	s.erase(find_if(s.rbegin(), s.rend(), not1(ptr_fun<int, int>(isspace))).base(), s.end());
	return s;
}

//
// trim from both ends
//
inline std::string& trim(std::string &s) 
{
	return ltrim(rtrim(s));
}

template<typename charT>
struct ci_equal
{
	ci_equal(const std::locale& loc) : m_loc(loc) {}
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
	typename T::const_iterator it = std::search(str1.begin(), str1.end(),
		str2.begin(), str2.end(), ci_equal<typename T::value_type>(loc) );
	if(it != str1.end()) { return it - str1.begin(); }
	return -1;
}

inline std::string& replace_in_place(string& str, const std::string& search, const std::string& replacement)
{
	std::string::size_type ssz = search.length();
	std::string::size_type rsz = replacement.length();
	std::string::size_type pos = 0;
	while((pos = str.find(search, pos)) != string::npos)
	{
		str.replace(pos, ssz, replacement);
		pos += rsz;
		ASSERT(pos <= str.length());
	}
	return str;
}

inline std::string replace(const std::string& str, const std::string& search, const std::string& replacement)
{
	std::string s(str);
	replace_in_place(s, search, replacement);
	return s;
}
