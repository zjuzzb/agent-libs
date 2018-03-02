// usage: metric_limits [size] [cache_size] [filters]

// size defaults to this, if no cache_size on cmd line, it defaults to size
#define METRIC_SIZE 10000


#ifndef ASSERT
#define ASSERT(x)
#endif

#include "metric_limits.cpp"

#include "stopwatch.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <fstream>
#include <unistd.h>


int main(int argc, char *argv[])
{
	unsigned long msz = METRIC_SIZE;
	unsigned long csz = msz;
	unsigned long fsz;

	if(argc > 1)
	{
		msz = strtoul(argv[1], 0, 10);
	}
	if(!msz)
	{
		std::cerr << "invalid metric size: " << msz << std::endl;
		return -1;
	}
	fsz = msz;
	if(argc > 2)
	{
		csz = strtoul(argv[2], 0, 10);
	}
	if(argc > 3)
	{
		fsz = strtoul(argv[3], 0, 10);
	}
	filter_vec_t f;
	for(int i; i < fsz; ++i)
	{
		f.push_back({std::to_string(i).append("?xyz*123"), i % 2});
	}

	std::cout << f.size() << " filters, " << msz << " metrics (" << csz << " cache)" << std::endl;

	{
		metric_limits ml(f, csz, 3u);

		sinsp_stopwatch sw;
		for(int j = 0; j < 10; ++j)
		{
			std::chrono::nanoseconds::rep sum = 0;
			for(unsigned i = 0; i < msz; ++i)
			{
				std::string s(std::to_string(i) + "xyz123");
				sw.start();
				std::string f;
				bool b = ml.allow(s, f);
				sw.stop();
				sum += sw.elapsed<std::chrono::nanoseconds>();
			}
			std::cout << "lookup: total=" << sum/1000 << " us, avg=" << sum/msz << " ns" << std::endl;
		}
		if(ml.cached())
		{
			// let cache expire
			std::cout << "Wait " << ml.cache_expire_seconds() + 1 << "s for cache to expire ..." << std::endl;
			sleep(ml.cache_expire_seconds() + 1);
			sw.start();
			std::string f;
			bool b = ml.allow("xyz", f);
			sw.stop();
			std::cout << "Cache purged from " << csz << " to " << ml.cached() << " in " << sw.elapsed<std::chrono::nanoseconds>()/1000 << " us" << std::endl;
		}
	}
	return 0;
}
