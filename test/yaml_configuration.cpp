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
	EXPECT_EQ(4, merged.size());
}

TEST(yaml_conf, get_events)
{
	yaml_configuration conf("resources/test.yaml", "");
	set<string> evts = conf.get_sequence<set<string>>("events", "docker", "volume");
	ASSERT_EQ(evts.size(), 4);
	ASSERT_TRUE(evts.find("create") != evts.end());
	ASSERT_TRUE(evts.find("destroy") != evts.end());
	ASSERT_TRUE(evts.find("mount") != evts.end());
	ASSERT_TRUE(evts.find("unmount") != evts.end());

	evts = conf.get_sequence<set<string>>("events", "docker", "container");
	ASSERT_EQ(evts.size(), 20);
	ASSERT_TRUE(evts.find("attach") != evts.end());
	ASSERT_TRUE(evts.find("commit") != evts.end());
	ASSERT_TRUE(evts.find("copy") != evts.end());
	ASSERT_TRUE(evts.find("create") != evts.end());
	ASSERT_TRUE(evts.find("destroy") != evts.end());
	ASSERT_TRUE(evts.find("die") != evts.end());
	ASSERT_TRUE(evts.find("exec_create") != evts.end());
	ASSERT_TRUE(evts.find("exec_start") != evts.end());
	ASSERT_TRUE(evts.find("export") != evts.end());
	ASSERT_TRUE(evts.find("kill") != evts.end());
	ASSERT_TRUE(evts.find("oom") != evts.end());
	ASSERT_TRUE(evts.find("pause") != evts.end());
	ASSERT_TRUE(evts.find("rename") != evts.end());
	ASSERT_TRUE(evts.find("resize") != evts.end());
	ASSERT_TRUE(evts.find("restart") != evts.end());
	ASSERT_TRUE(evts.find("start") != evts.end());
	ASSERT_TRUE(evts.find("stop") != evts.end());
	ASSERT_TRUE(evts.find("top") != evts.end());
	ASSERT_TRUE(evts.find("unpause") != evts.end());
	ASSERT_TRUE(evts.find("update") != evts.end());

	set<string, ci_compare> evts2 = conf.get_sequence<set<string, ci_compare>>("events", "kubernetes", "replicationController");
	ASSERT_EQ(evts2.size(), 1);
	ASSERT_TRUE(evts.find("ALL") != evts2.end());

	evts2 = conf.get_sequence<set<string, ci_compare>>("events", "kubernetes", "node");
	ASSERT_EQ(evts2.size(), 1);
	ASSERT_TRUE(evts.find("ALL") != evts2.end());

	evts2 = conf.get_sequence<set<string, ci_compare>>("events", "kubernetes", "pod");
	ASSERT_EQ(evts2.size(), 4);
	ASSERT_TRUE(evts.find("added") != evts2.end());
	ASSERT_TRUE(evts.find("modified") != evts2.end());
	ASSERT_TRUE(evts.find("deleted") != evts2.end());
	ASSERT_TRUE(evts.find("error") != evts2.end());

	vector<int> ints = conf.get_sequence<vector<int>>("deep", "level1", "level2", "level3", "level4", "level5");
	ASSERT_EQ(ints.size(), 3);
	ASSERT_EQ(ints[0], 1);
	ASSERT_EQ(ints[1], 2);
	ASSERT_EQ(ints[2], 3);
}