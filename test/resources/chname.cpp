#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <vector>
#include <memory>
#include <string.h>
#include <functional>

void run()
{
	//std::thread::id this_id = std::this_thread::get_id();
	while(true)
	{
		//std::cout << this_id << ": running..." << std::endl;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

void changer(char **argv)
{
	char pname[] = "sysdig";
    memcpy((void *)argv[0], pname, sizeof(pname));
	//std::thread::id this_id = std::this_thread::get_id();
	while(true)
	{
		//std::cout << this_id << ": running..." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}
}

int main(int argc, char **argv)
{
  char pname[] = "savonarola";
  prctl(PR_SET_NAME, (unsigned long) &pname, 0, 0, 0);
  std::vector<std::shared_ptr<std::thread>> threads;
  for(int j=0; j < 20; ++j)
  {
  	threads.push_back(std::make_shared<std::thread>(run));
  }

  auto binded_changer = std::bind(changer, argv);
  std::thread changer(binded_changer);
  run();
}

