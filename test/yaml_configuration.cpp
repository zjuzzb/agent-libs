#include <gtest.h>
#include "sys_call_test.h"
#include <configuration.h>

using namespace std;

TEST(yaml_conf, get_scalar)
{
	yaml_configuration conf("resources/test.yaml", "resources/test.default.yaml");
	EXPECT_EQ("mystring", conf.get_scalar<string>("mykey", ""));
	EXPECT_EQ("value", conf.get_scalar<string>("mykeydefault", ""));
	EXPECT_EQ("value", conf.get_scalar<string>("mykeynotpresent", "value"));
	EXPECT_EQ(true, conf.get_scalar<bool>("mybool", false));
	EXPECT_EQ(6666, conf.get_scalar<int>("server", "port", 0));
	EXPECT_EQ("collector-staging.sysdigcloud.com", conf.get_scalar<string>("server", "address", ""));

	yaml_configuration conf2("resources/test2.yaml", "resources/test.default.yaml");
	EXPECT_EQ("myvaluedefault", conf2.get_scalar<string>("mykey", ""));
}

TEST(yaml_conf, get_merged_map)
{
	yaml_configuration conf("resources/test.yaml", "resources/test.default.yaml");
	auto merged = conf.get_merged_map<map<string,int>>("mynested");
	EXPECT_EQ(78, merged["firstkey"]["subkey"]);
	EXPECT_EQ(40, merged["secondkey"]["subkey"]);
	auto empty = conf.get_merged_map<map<string,int>>("mynestedempty");
	EXPECT_TRUE(empty.empty());
}

TEST(yaml_conf, get_merged_sequence)
{
	yaml_configuration conf("resources/test.yaml", "resources/test.default.yaml");
	auto merged = conf.get_merged_sequence<int>("myarray");
	EXPECT_EQ(3, merged.size());
}