#include <gtest.h>
#include <configuration.h>
#include "sys_call_test.h"

using namespace std;

TEST(yaml_conf, getScalar)
{
	yaml_configuration conf("resources/test.yaml", "resources/test.default.yaml");
	EXPECT_EQ("mystring", conf.get_scalar<string>("mykey", ""));
}