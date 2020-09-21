#include "wall_time.h"
#include <sys/time.h>

namespace
{
	const uint64_t ONE_SECOND_IN_NS = 1000000000LL;
}

namespace wall_time
{

uint64_t nanoseconds()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);

	return tv.tv_sec * (uint64_t) 1000000000 + tv.tv_usec * 1000;
}

uint64_t seconds()
{
	return nanoseconds() / ONE_SECOND_IN_NS;
}


}
