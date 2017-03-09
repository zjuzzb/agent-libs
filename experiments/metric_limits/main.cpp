//#include "sparsepp/spp.h"
//#define SPARSEPP_MAP

//#include <sparsehash/dense_hash_map>
//#define DENSE_HASH_MAP

#include "metric_limits.cpp"

#include "stopwatch.h"
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char *argv[])
{
	unsigned sz = 3000;
	if(argc > 1) sz = atoi(argv[1]);
	std::vector<std::string> excluded{{"haproxy.*", "redis.*", "test.*", "test2.*.somethin?","1haproxy.*", "2redis.*", "3test.*", "4test2.*.somethin?"}};
	std::vector<std::string> included{{"haproxy.backend*", "test.*", "test2.*.?othin?","1haproxy.backend*", "2test.*", "3test2.*.?othin?"}};
	metric_limits ml(excluded, included, sz);

	for(int j = 0; j < 20; ++j)
	{
		sinsp_stopwatch sw;
		std::chrono::nanoseconds::rep sum = 0;
		for(unsigned i = 0; i < ml.cache_max_entries(); ++i)
		{
			std::string s(std::to_string(i) + "xyz123");
			sw.start();
			bool b = ml.allow(s);
			sw.stop();
			sum += sw.elapsed<std::chrono::nanoseconds>();
		}
		sw.stop();
		std::cout << "total=" << sum/1000 << " ms, avg=" << sum/ml.cache_max_entries() << " ns" << std::endl;
	}
	return 0;
}
