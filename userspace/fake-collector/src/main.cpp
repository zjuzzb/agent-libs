#include "fake_collector.h"
#include <iostream>
#include <unistd.h>

int main(int argc, char **argv)
{
	fake_collector fc;

	fc.start(0);

	std::cout << "Fake collector started at port " << fc.get_port() << std::endl;
	sleep(60);

	fc.stop();

	std::cout << "Received data:" << std::endl;
	while (fc.has_data())
	{
		auto b = fc.pop_data();
		printf("\t\"%s\"\n", b.ptr);
		delete[] b.ptr;
	}

	return 0;
}
