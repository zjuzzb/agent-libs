/**
 * @file
 *
 * Interface to statsd-specific loggging.
 *
 * Note: Use of this is limited only to temp debugging associated with
 *       SMAGENT-1889.  This is not intended to be a general-purpose API.
 *       It will be removed in a near-future update.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <chrono>
#include <cstdio>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

extern FILE* s_statsd_log_file;
extern bool s_statsd_log_enabled;
      
#define gettid() ((pid_t) syscall(SYS_gettid))

#define STATSD_LOG(fmt, ...)                                                                                      \
	do {                                                                                                      \
		if(s_statsd_log_enabled) {                                                                        \
		        if(s_statsd_log_file == nullptr) {                                                        \
		        	s_statsd_log_file = fopen("/opt/draios/logs/statsd.log", "a");                    \
		        	fprintf(s_statsd_log_file, "-----------------------------------------------\n");  \
		        }                                                                                         \
		        fprintf(s_statsd_log_file, "[%ld][%d/%d][%s:%d]: %s: " fmt "\n",                          \
		                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(), \
		                getpid(), gettid(), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__);             \
		        fflush(s_statsd_log_file);                                                                \
		}                                                                                                 \
	} while(false)
