#pragma once

#ifndef SYSDIG_TEST
#include <gperftools/profiler.h>
#endif

/**
 * Helper namespace to control the profiler. This mostly exists
 * because tcmalloc doesn't get along well with helgrind so we
 * compile it out of the test binaries.
 */
namespace utils {
namespace profiler {

/**
 * Start the profiler
 */
void start(const std::string &filename)
{
#ifndef SYSDIG_TEST
	ProfilerStart(filename.c_str());
#endif
}

/**
 * Stop the profiler
 */
void stop()
{
#ifndef SYSDIG_TEST
	ProfilerStop();
#endif
}

}
}
