/**
 * @file
 *
 * Contains the debug assert macro used throughout the agent.
 *
 * Copyright (c) 2019 Sysdig Inc. All rights reserved.
 */
#pragma once

#include <assert.h>
#include <string>

#include <Poco/Format.h>

// This file also requires logger.h, but including it would cause the 
// universe to implode.

#undef ASSERT

// Only assert on DEBUG builds
#ifdef _DEBUG

extern std::unique_ptr<common_logger> g_log;

#define ASSERT(X) \
	if(!(X)) \
	{ \
		if(g_log) \
		{ \
	        g_log->error(Poco::format("ASSERTION %s at %s:%d", std::string(#X), std::string(__FILE__), __LINE__)); \
		} \
		assert(X); \
	}
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

