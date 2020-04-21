#include <dirent.h>
#include <sys/stat.h>
#include "jni_utils.h"


int hsperfdata_utils::scandir_selector(const struct dirent *dir)
{
	static const char* HSPERF = "hsperfdata_";

	if(std::string(dir->d_name).substr(0, LENGTH(HSPERF)) == HSPERF)
	{
		return 1;
	}

	return 0;
}

std::string hsperfdata_utils::find_hsperfdata_by_pid(uint32_t pid)
{
	std::string ret;
	bool found = false;
 	struct dirent **hsperf_list;
	const std::string pid_str = std::to_string(pid);
	int hsfiles_count = scandir("/tmp", &hsperf_list, scandir_selector, nullptr);

	struct stat hsperf_stat;
	for(int i=0; i<hsfiles_count; i++)
	{
		if(!found)
		{
			std::string hsperf_file = std::string("/tmp/") + hsperf_list[i]->d_name + "/" + pid_str;
			if(stat(hsperf_file.c_str(), &hsperf_stat) == 0)
			{
				found = true;
				ret = std::move(hsperf_file);
			}
		}
		free(hsperf_list[i]);
	}
	free(hsperf_list);
	return ret;
}

