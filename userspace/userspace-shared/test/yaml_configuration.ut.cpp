#include <gtest.h>
#include <configuration_manager.h>

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

// Note: since the configuration map is global, these tests should not
// share keys among them and are not thread safe. 
//
// Note: these have to be global as well, or only sorta...but we'd have to allocate them
//       and never free them anyway....so...
//
type_config<bool> bool_not_there_true(true, "some test description", "bool_not_there_true");
type_config<bool> bool_not_there_false(false, "some test description", "bool_not_there_false");
type_config<bool> bool_true(false, "some test description", "bool_true");
type_config<bool> bool_false(false, "some test description", "bool_false");
type_config<bool> bool_true_nested(false, "some test description", "bool_nested","bool_true_nested");
type_config<bool> bool_false_nested(false, "some test description", "bool_nested","bool_false_nested");
type_config<bool> bool_true_double_nested(false, "some test description", "bool_double_nested","bool_double_nested_sub", "bool_true_double_nested");
type_config<bool> bool_false_double_nested(false, "some test description", "bool_double_nested","bool_double_nested_sub", "bool_false_double_nested");
type_config<uint64_t> uint64_t_config(1, "some test description", "int_12345");
type_config<bool> bool_true_1(false, "some test description", "bool_true_overlap");
type_config<bool> bool_true_2(false, "some test description", "bool_true_overlap");

TEST(yaml_conf, simple_config_test)
{
	yaml_configuration conf({"resources/test_simple_config.yaml"});

	// double check a couple of the values to make sure defaults are getting populated
	EXPECT_EQ(bool_not_there_true.get(), true);
	EXPECT_EQ(bool_not_there_false.get(), false);
	EXPECT_EQ(uint64_t_config.get(), 1);

	// check that key strings work
	EXPECT_EQ(bool_true.get_key_string(), "bool_true");
	EXPECT_EQ(bool_true_nested.get_key_string(), "bool_nested.bool_true_nested");
	EXPECT_EQ(bool_true_double_nested.get_key_string(), "bool_double_nested.bool_double_nested_sub.bool_true_double_nested");

	// check that tostring works
	EXPECT_EQ(bool_true.to_string(), "bool_true: false");
	EXPECT_EQ(bool_false.to_string(), "bool_false: false");

	// actually read the configs now
	configuration_manager::init_config(conf);

	// check that all values are correct
	EXPECT_EQ(bool_not_there_true.get(), true);
	EXPECT_EQ(bool_not_there_false.get(), false);
	EXPECT_EQ(bool_true.get(), true);
	EXPECT_EQ(bool_false.get(), false);
	EXPECT_EQ(bool_true_nested.get(), true);
	EXPECT_EQ(bool_false_nested.get(), false);
	EXPECT_EQ(bool_true_double_nested.get(), true);
	EXPECT_EQ(bool_false_double_nested.get(), false);

	// check that to_string is updated
	EXPECT_EQ(bool_true.to_string(), "bool_true: true");

	// check the int variant works
	EXPECT_EQ(uint64_t_config.get(), 12345);
	EXPECT_EQ(uint64_t_config.to_string(), "int_12345: 12345");

	// second bool doesn't pick up value. should be a log in the log
	EXPECT_EQ(bool_true_1.get(), true);
	EXPECT_EQ(bool_true_2.get(), false);

	// double check get const works on something
	EXPECT_EQ(bool_true.get_const(), true);
	EXPECT_EQ(uint64_t_config.get_const(), 12345);
}

