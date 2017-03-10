// usage: metric_limits [size] [cache_size]

// size defaults to this, if no cache_size on cmd line, it defaults to size
#define METRIC_SIZE 6000

#include "metric_limits.cpp"

#include "stopwatch.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

int main(int argc, char *argv[])
{
	unsigned long msz = METRIC_SIZE;
	unsigned long csz = msz;

	if(argc > 1) msz = strtoul(argv[1], 0, 10);
	if(!msz)
	{
		std::cerr << "invalid metric size: " << msz << std::endl;
		return -1;
	}
	if(argc > 2)
	{
		csz = strtoul(argv[2], 0, 10);
	}
	std::cout << msz << " metrics, " << csz << " cached" << std::endl;

	metrics_filter_vec f({{"haproxy.backend*", true}, {"test.*", true}, {"test2.*.?othin?", true}, {"1haproxy.backend*", true}, {"2test.*", true}, {"3test2.*.?othin?", true},
						  {"haproxy.backend*", false}, {"test.*", false}, {"test2.*.?othin?", false}, {"1haproxy.backend*", false}, {"2test.*", false}, {"3test2.*.?othin?", false}});
	metric_limits ml(f, csz);

	sinsp_stopwatch sw;
	for(int j = 0; j < 10; ++j)
	{
		std::chrono::nanoseconds::rep sum = 0;
		for(unsigned i = 0; i < msz; ++i)
		{
			std::string s(std::to_string(i) + "xyz123");
			sw.start();
			bool b = ml.allow(s);
			sw.stop();
			sum += sw.elapsed<std::chrono::nanoseconds>();
		}
		std::cout << "total=" << sum/1000 << " us, avg=" << sum/msz << " ns" << std::endl;
	}
	return 0;
}
