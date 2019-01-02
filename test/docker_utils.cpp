#include <stdlib.h>
#include <stdio.h>

#include <string>

#include <gtest.h>

#include "docker_utils.h"

using namespace std;

bool dutils_check_docker()
{
	if(system("service docker status > /dev/null 2>&1") != 0)
	{
		if (system("systemctl status docker > /dev/null 2>&1") != 0) {
			printf("Docker not running, skipping test\n");
			return false;
		}
	}

	// We depend on docker versions >= 1.10
	if(system("docker --version | grep -qE \"Docker version 1.[56789].\"") == 0)
	{
		printf("Docker version too old, skipping test\n");
		return false;
	}

	return true;
}

void dutils_create_tag(const char *tag, const char *image)
{
	std::string tag_cmd = string("docker tag ") + image + " " + tag + " > /dev/null 2>&1";
	std::string remove_tag_cmd = string("(docker rmi ") + tag + " || true) > /dev/null 2>&1";

	EXPECT_EQ(system(remove_tag_cmd.c_str()), 0);
	EXPECT_EQ(system(tag_cmd.c_str()), 0);
}

void dutils_kill_container(const char *name)
{
	std::string kill_cmd = string("(docker kill ") + name + " || true) > /dev/null 2>&1";
	std::string rm_cmd = string("(docker rm -fv ") + name + " || true) > /dev/null 2>&1";

	EXPECT_EQ(system(kill_cmd.c_str()), 0);
	EXPECT_EQ(system(rm_cmd.c_str()), 0);
}

void dutils_kill_image(const char *image)
{
	std::string rmi_cmd = string("(docker rmi ") + image + " || true) > /dev/null 2>&1";

	EXPECT_EQ(system(rmi_cmd.c_str()), 0);
}
