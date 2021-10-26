#pragma once
#include <cstdint>
#include <cstddef>
#include <sys/time.h>
/**
 * Stuff that we don't know where else it should go!
 */
namespace agent_utils
{
inline uint64_t get_current_ts_ns()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * (uint64_t)1000000000 + tv.tv_usec * 1000;
}
}  // namespace agent_utils
