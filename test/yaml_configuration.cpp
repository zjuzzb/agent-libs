#include <gtest.h>
#include "sys_call_test.h"
#include <configuration.h>
#include "proc_config.h"
#include "app_checks.h"
#include "metric_limits.h"

using namespace std;

TEST(proc_config, test_correct)
{
	proc_config config("{app_checks: [{ name: redisdb, pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} }] }");
	auto checks = config.app_checks();
	EXPECT_EQ(1U, checks.size());
}

TEST(proc_config, test_wrong_yaml_syntax)
{
	proc_config config("app_checks: [{ name: redisdb, pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} }] }");
	auto checks = config.app_checks();
	EXPECT_EQ(0U, checks.size());
}

TEST(proc_config, test_wrong_yaml_objects)
{
	// app_checks is not a list
	proc_config config("{ app_checks: { name: redisdb, pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} } }");
	auto checks = config.app_checks();
	EXPECT_EQ(0U, checks.size());

	// missing name
	config = proc_config("{app_checks: [{ pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} }] }");
	checks = config.app_checks();
	EXPECT_EQ(0U, checks.size());

	// conf not an object
	config = proc_config("{app_checks: [{ name: redisdb, pattern: {comm: redis-server}, conf: 127.0.0.1 }] }");
	checks = config.app_checks();
	EXPECT_EQ(1U, checks.size()); // Parsed with an empty conf

	// a wrong one and a right one
	config = proc_config("{app_checks: [{ pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} }, { name: redis, pattern: {comm: redis-server}, conf: { host: 127.0.0.1, port: 6379, password: protected} }] }");
	checks = config.app_checks();
	EXPECT_EQ(0U, checks.size());

	// empty yaml, legit
	config = proc_config("");
	checks = config.app_checks();
	EXPECT_EQ(0U, checks.size());
}

TEST(yaml_to_json, test_sequence)
{
	auto node = YAML::Load("[test, 3, test3]");
	auto json = yaml_to_json(node);
	EXPECT_TRUE(json.isArray());
	EXPECT_EQ("test", json[0].asString());
	EXPECT_EQ(3, json[1].asInt());
	EXPECT_EQ("test3", json[2].asString());
}

TEST(yaml_to_json, test_map)
{
	auto node = YAML::Load("{ test: \"http://localhost:{port}\", int: 3, f: 1.56, bool1: true, bool2: false, bool3: True }");
	auto json = yaml_to_json(node);
	EXPECT_TRUE(json.isObject());
	EXPECT_EQ("http://localhost:{port}", json["test"].asString());
	EXPECT_EQ(3, json["int"].asInt());
	EXPECT_EQ(1.56, json["f"].asDouble());
	EXPECT_TRUE(json["bool1"].isBool());
	EXPECT_TRUE(json["bool1"].asBool());
	EXPECT_TRUE(json["bool2"].isBool());
	EXPECT_FALSE(json["bool2"].asBool());
	EXPECT_TRUE(json["bool3"].isBool());
	EXPECT_TRUE(json["bool3"].asBool());
}

TEST(yaml_to_json, test_nested)
{
	auto node = YAML::Load("{ test: \"http://localhost:{port}\", v: [{o: 9, p:\"test\"}, {\"l\":\"{}\" }] }");
	auto json = yaml_to_json(node);
	EXPECT_TRUE(json.isObject());
	EXPECT_EQ("http://localhost:{port}", json["test"].asString());
	EXPECT_EQ("{}", json["v"][1]["l"].asString());
	EXPECT_EQ(9, json["v"][0]["o"].asInt());
}

TEST(yaml_conf, metric_filter)
{
	yaml_configuration conf({"resources/test_filters.yaml"});
	filter_vec_t mf = conf.get_merged_sequence<user_configured_filter>("metrics_filter");
	EXPECT_EQ(11U, mf.size());
	EXPECT_FALSE(metric_limits::first_includes_all(mf));
	EXPECT_TRUE(mf[0].to_string() == "redis.cpu.*");
	EXPECT_TRUE(mf[1].to_string() == "redis.mem.lua");
	EXPECT_TRUE(mf[2].to_string() == "redis.mem.*");
	EXPECT_TRUE(mf[3].to_string() == "ThreadCount");
	EXPECT_TRUE(mf[4].to_string() == "mesos.framework.cpu");
	EXPECT_TRUE(mf[5].to_string() == "mesos.fr*");
	EXPECT_TRUE(mf[6].to_string() == "test.*");
	EXPECT_TRUE(mf[7].to_string() == "test.*");
	EXPECT_TRUE(mf[8].to_string() == "haproxy.backend.*");
	EXPECT_TRUE(mf[9].to_string() == "haproxy.*");
	EXPECT_TRUE(mf[10].to_string() == "redis.*");
}
