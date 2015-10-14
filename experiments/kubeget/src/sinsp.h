#pragma once

#include <iostream>

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
		if(g_log) \
		{ \
			g_log->error(Poco::format("ASSERTION %s at %s:%d", string(#X), string(__FILE__), __LINE__)); \
		} \
		assert(X); \
	} 
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG
