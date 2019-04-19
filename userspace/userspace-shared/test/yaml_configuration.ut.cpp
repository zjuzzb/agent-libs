#include "yaml_configuration.h"
#include <gtest.h>

using namespace std;

namespace {
// Duplicated from sysdig utils
struct ci_compare
{
	// less-than, for use in STL containers
	bool operator ()(const std::string& a, const std::string& b) const
	{
#ifndef _WIN32
		return strcasecmp(a.c_str(), b.c_str()) < 0;
#else
		return lstrcmpiA(a.c_str(), b.c_str()) < 0;
#endif // _WIN32
	}

	static bool is_equal(const std::string& a, const std::string& b)
	{
#ifndef _WIN32
		return strcasecmp(a.c_str(), b.c_str()) == 0;
#else
		return lstrcmpiA(a.c_str(), b.c_str()) == 0;
#endif // _WIN32
	}
};
}

TEST(yaml_conf, get_scalar)
{
	yaml_configuration conf {"resources/test.yaml", "resources/test.default.yaml"};
	EXPECT_EQ("mystring", conf.get_scalar<string>("mykey", ""));
	EXPECT_EQ("value", conf.get_scalar<string>("mykeydefault", ""));
	EXPECT_EQ("value", conf.get_scalar<string>("mykeynotpresent", "value"));
	EXPECT_EQ(true, conf.get_scalar<bool>("mybool", false));
	EXPECT_EQ(6666, conf.get_scalar<int>("server", "port", 0));
	EXPECT_EQ("collector-staging.sysdigcloud.com", conf.get_scalar<string>("server", "address", ""));
	EXPECT_EQ(40, conf.get_scalar<int>("mynested", "secondkey", "subkey", -1));

	yaml_configuration conf2({"resources/test2.yaml", "resources/test.default.yaml"});
	EXPECT_EQ("myvaluedefault", conf2.get_scalar<string>("mykey", ""));
}

TEST(yaml_conf, get_first_deep_map)
{
	yaml_configuration conf({"resources/test.yaml", "resources/test.default.yaml"});
	auto deep = conf.get_first_deep_map<int>("mydeepnested", "key");
	EXPECT_EQ(41, deep["firstkey"]);
	EXPECT_EQ(87, deep["secondkey"]);
	auto empty = conf.get_first_deep_map<int>("mynestedempty");
	EXPECT_TRUE(empty.empty());
}

TEST(yaml_conf, get_merged_map)
{
	yaml_configuration conf({"resources/test.yaml", "resources/test.default.yaml"});
	auto merged = conf.get_merged_map<map<string,int>>("mynested");
	EXPECT_EQ(78, merged["firstkey"]["subkey"]);
	EXPECT_EQ(40, merged["secondkey"]["subkey"]);
	auto empty = conf.get_merged_map<map<string,int>>("mynestedempty");
	EXPECT_TRUE(empty.empty());
}

TEST(yaml_conf, get_merged_sequence)
{
	yaml_configuration conf({"resources/test.yaml", "resources/test.default.yaml"});
	auto merged = conf.get_merged_sequence<int>("myarray");
	EXPECT_EQ(3U, merged.size());
}

TEST(yaml_conf, get_deep_merged_sequence)
{
	yaml_configuration conf({"resources/test.yaml", "resources/test.default.yaml"});
	set<string> evts = conf.get_deep_merged_sequence<set<string>>("events", "docker", "volume");
	ASSERT_EQ(evts.size(), 5U);
	ASSERT_TRUE(evts.find("all") != evts.end());
	ASSERT_TRUE(evts.find("create") != evts.end());
	ASSERT_TRUE(evts.find("destroy") != evts.end());
	ASSERT_TRUE(evts.find("mount") != evts.end());
	ASSERT_TRUE(evts.find("unmount") != evts.end());

	evts = conf.get_deep_merged_sequence<set<string>>("events", "docker", "container");
	ASSERT_EQ(evts.size(), 21U);
	ASSERT_TRUE(evts.find("all") != evts.end());
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

	set<string, ci_compare> evts2 = conf.get_deep_merged_sequence<set<string, ci_compare>>("events", "kubernetes", "replicationController");
	ASSERT_EQ(evts2.size(), 1U);
	ASSERT_TRUE(evts2.find("ALL") != evts2.end());

	evts2 = conf.get_deep_merged_sequence<set<string, ci_compare>>("events", "kubernetes", "node");
	ASSERT_EQ(evts2.size(), 1U);
	ASSERT_TRUE(evts2.find("ALL") != evts2.end());

	evts2 = conf.get_deep_merged_sequence<set<string, ci_compare>>("events", "kubernetes", "pod");
	ASSERT_EQ(evts2.size(), 4U);
	ASSERT_TRUE(evts2.find("added") != evts2.end());
	ASSERT_TRUE(evts2.find("modified") != evts2.end());
	ASSERT_TRUE(evts2.find("deleted") != evts2.end());
	ASSERT_TRUE(evts2.find("error") != evts2.end());

	vector<int> ints = conf.get_deep_merged_sequence<vector<int>>("deep", "level1", "level2", "level3", "level4", "level5");
	ASSERT_EQ(ints.size(), 3U);
	ASSERT_EQ(ints[0], 1);
	ASSERT_EQ(ints[1], 2);
	ASSERT_EQ(ints[2], 3);

	evts2 = conf.get_deep_merged_sequence<set<string, ci_compare>>("events2", "docker", "container");
	ASSERT_EQ(evts2.size(), 6U);
	ASSERT_TRUE(evts2.find("attach") != evts2.end());
	ASSERT_TRUE(evts2.find("commit") != evts2.end());
	ASSERT_TRUE(evts2.find("copy") != evts2.end());
	ASSERT_TRUE(evts2.find("create") != evts2.end());
	ASSERT_TRUE(evts2.find("destroy") != evts2.end());
	ASSERT_TRUE(evts2.find("die") != evts2.end());

	evts2 = conf.get_deep_merged_sequence<set<string, ci_compare>>("events2", "docker", "image");
	ASSERT_EQ(evts2.size(), 3U);
	ASSERT_TRUE(evts2.find("delete") != evts2.end());
	ASSERT_TRUE(evts2.find("import") != evts2.end());
	ASSERT_TRUE(evts2.find("pull") != evts2.end());
}


TEST(yaml_conf, get_deep_sequence)
{
	yaml_configuration conf {"resources/test.yaml", "resources/test.default.yaml" };
	const auto& roots = conf.get_roots();
	ASSERT_EQ(2U, roots.size());

	set<string> evts = yaml_configuration::get_deep_sequence<set<string>>(conf, roots[0], "events", "docker", "volume");
	ASSERT_EQ(evts.size(), 4U);
	ASSERT_TRUE(evts.find("create") != evts.end());
	ASSERT_TRUE(evts.find("destroy") != evts.end());
	ASSERT_TRUE(evts.find("mount") != evts.end());
	ASSERT_TRUE(evts.find("unmount") != evts.end());

	evts = yaml_configuration::get_deep_sequence<set<string>>(conf, roots[1], "events", "docker", "volume");
	ASSERT_EQ(evts.size(), 1U);
	ASSERT_TRUE(evts.find("all") != evts.end());

	evts = yaml_configuration::get_deep_sequence<set<string>>(conf, roots[0], "events", "docker", "container");
	ASSERT_EQ(evts.size(), 20U);
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

	evts = yaml_configuration::get_deep_sequence<set<string>>(conf, roots[1], "events", "docker", "container");
	ASSERT_EQ(evts.size(), 1U);
	ASSERT_TRUE(evts.find("all") != evts.end());

	set<string, ci_compare> evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[0], "events", "kubernetes", "replicationController");
	ASSERT_EQ(evts2.size(), 1U);
	ASSERT_TRUE(evts2.find("ALL") != evts2.end());

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[1], "events", "kubernetes", "replicationController");
	ASSERT_EQ(evts2.size(), 0U);

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[0], "events", "kubernetes", "node");
	ASSERT_EQ(evts2.size(), 1U);
	ASSERT_TRUE(evts2.find("ALL") != evts2.end());

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[1], "events", "kubernetes", "node");
	ASSERT_EQ(evts2.size(), 0U);

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[0], "events", "kubernetes", "pod");
	ASSERT_EQ(evts2.size(), 4U);
	ASSERT_TRUE(evts2.find("added") != evts2.end());
	ASSERT_TRUE(evts2.find("modified") != evts2.end());
	ASSERT_TRUE(evts2.find("deleted") != evts2.end());
	ASSERT_TRUE(evts2.find("error") != evts2.end());

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[1], "events", "kubernetes", "pod");
	ASSERT_EQ(evts2.size(), 0U);

	vector<int> ints = yaml_configuration::get_deep_sequence<vector<int>>(conf, roots[0], "deep", "level1", "level2", "level3", "level4", "level5");
	ASSERT_EQ(ints.size(), 3U);
	ASSERT_EQ(ints[0], 1);
	ASSERT_EQ(ints[1], 2);
	ASSERT_EQ(ints[2], 3);

	ints = yaml_configuration::get_deep_sequence<vector<int>>(conf, roots[1], "deep", "level1", "level2", "level3", "level4", "level5");
	ASSERT_EQ(ints.size(), 0U);

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[0], "events2", "docker", "container");
	ASSERT_EQ(evts2.size(), 4U);
	ASSERT_TRUE(evts2.find("attach") != evts2.end());
	ASSERT_TRUE(evts2.find("create") != evts2.end());
	ASSERT_TRUE(evts2.find("commit") != evts2.end());
	ASSERT_TRUE(evts2.find("copy") != evts2.end());

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[1], "events2", "docker", "container");
	ASSERT_EQ(evts2.size(), 4U);
	ASSERT_TRUE(evts2.find("attach") != evts2.end());
	ASSERT_TRUE(evts2.find("create") != evts2.end());
	ASSERT_TRUE(evts2.find("destroy") != evts2.end());
	ASSERT_TRUE(evts2.find("die") != evts2.end());

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[0], "events2", "docker", "image");
	ASSERT_EQ(evts2.size(), 3U);
	ASSERT_TRUE(evts2.find("delete") != evts2.end());
	ASSERT_TRUE(evts2.find("import") != evts2.end());
	ASSERT_TRUE(evts2.find("pull") != evts2.end());

	evts2 = yaml_configuration::get_deep_sequence<set<string, ci_compare>>(conf, roots[1], "events2", "docker", "image");
	ASSERT_EQ(evts2.size(), 0U);
}
