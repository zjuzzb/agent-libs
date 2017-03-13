#include <gtest.h>
#include "sys_call_test.h"
#include "app_checks.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include <fstream>
#include "third-party/jsoncpp/json/json.h"

class app_checks_proxy_f : public ::testing::Test {
protected:
	virtual void SetUp() {
		m_inqueue = make_unique<posix_queue>("/sdc_app_checks_out", posix_queue::SEND, 1);
		app_checks = make_unique<app_checks_proxy>();
	}

	virtual void TearDown() {
		m_inqueue.reset();
		app_checks.reset();
	}

	void use_json(const char *json)
	{
		string resource("resources/");
		resource += json;
		ifstream json_file(resource);
		getline(json_file, m_jsondata);
		m_inqueue->send(m_jsondata);
	}

	unique_ptr<posix_queue> m_inqueue;
	unique_ptr<app_checks_proxy> app_checks;
	string m_jsondata;
};

TEST_F(app_checks_proxy_f, read_ok)
{
	use_json("app_checks_ok.json");
	auto metrics = app_checks->read_metrics();
	EXPECT_EQ(2U, metrics.size());
}

void print(const app_checks_proxy::metric_map_t& metrics)
{
	//unordered_map<int, map<string, app_check_data>>
	for(auto app : metrics)
	{
		int metric = 0, services = 0;
		std::cout << app.first << std::endl;
		for(auto acd : app.second)
		{
			std::cout << '\t' << acd.first << std::endl;
			for(auto m : acd.second.metrics())
			{
				std::cout << "\t\t" << m.name() << std::endl;
				++metric;
			}
			for(auto d : acd.second.services())
			{
				std::cout << "\t\t" << d.name() << std::endl;
				++services;
			}
		}
		std::cout << "-------" << std::endl;
		std::cout << metric << " metrics" << std::endl;
		std::cout << services << " services" << std::endl;
	}
}

template <typename T>
bool has(const T& svcs, const std::string& name)
{
	for(auto s : svcs)
	{
		if(s.name() == name)
		{
			return true;
		}
	}
	return false;
}

TEST_F(app_checks_proxy_f, filters)
{
	use_json("app_checks_ok.json");
	auto metrics = app_checks->read_metrics(nullptr);
	ASSERT_EQ(2U, metrics.size());
	//print(metrics);
	EXPECT_EQ(0, metrics[2115].begin()->second.metrics().size());
	EXPECT_EQ(1u, metrics[2115].begin()->second.services().size());
	EXPECT_EQ(31u, metrics[805].begin()->second.metrics().size());
	EXPECT_EQ(1u, metrics[805].begin()->second.services().size());
	app_check_data::metrics_t metric_list = metrics[805].begin()->second.metrics();
	EXPECT_TRUE(has(metric_list, "redis.keys.evicted"));
	EXPECT_TRUE(has(metric_list, "redis.net.slaves"));
	EXPECT_TRUE(has(metric_list, "redis.cpu.sys"));
	EXPECT_TRUE(has(metric_list, "redis.keys.expired"));
	EXPECT_TRUE(has(metric_list, "redis.rdb.last_bgsave_time"));
	app_check_data::services_t service_list = metrics[805].begin()->second.services();
	EXPECT_TRUE(has(service_list, "redis.can_connect"));

	metrics_filter_vec f({{"*", false}, {"*.can_connect", true}});
	metric_limits::sptr_t ml(new metric_limits(f));
	use_json("app_checks_ok.json");
	metrics = app_checks->read_metrics(ml);
	EXPECT_EQ(0, metrics.size());

	f = {{"redis.mem.*", true}, {"*.can_connect", true}, {"*", false}};
	ml.reset(new metric_limits(f));
	use_json("app_checks_ok.json");
	metrics = app_checks->read_metrics(ml);
	EXPECT_EQ(2U, metrics.size());

	metric_list = metrics[2115].begin()->second.metrics();
	EXPECT_EQ(0, metric_list.size());
	service_list = metrics[2115].begin()->second.services();
	EXPECT_EQ(1u, service_list.size());
	EXPECT_TRUE(has(service_list, "nginx.can_connect"));

	metric_list = metrics[805].begin()->second.metrics();
	EXPECT_EQ(5u, metric_list.size());
	EXPECT_TRUE(has(metric_list, "redis.mem.used"));
	EXPECT_TRUE(has(metric_list, "redis.mem.fragmentation_ratio"));
	EXPECT_TRUE(has(metric_list, "redis.mem.peak"));
	EXPECT_TRUE(has(metric_list, "redis.mem.lua"));
	EXPECT_TRUE(has(metric_list, "redis.mem.rss"));
	EXPECT_FALSE(has(metric_list, "redis.keys.evicted"));
	EXPECT_FALSE(has(metric_list, "redis.net.slaves"));
	EXPECT_FALSE(has(metric_list, "redis.cpu.sys"));
	EXPECT_FALSE(has(metric_list, "redis.keys.expired"));
	EXPECT_FALSE(has(metric_list, "redis.rdb.last_bgsave_time"));
	service_list = metrics[805].begin()->second.services();
	EXPECT_EQ(1u, service_list.size());
	EXPECT_TRUE(has(service_list, "redis.can_connect"));

	f = {{"*", false}, {"redis.mem.*", true}, {"*.can_connect", true}};
	ml.reset(new metric_limits(f));
	use_json("app_checks_ok.json");
	metrics = app_checks->read_metrics(ml);
	EXPECT_EQ(0, metrics.size());

	f = {{"*", false}};
	ml.reset(new metric_limits(f));
	use_json("app_checks_ok.json");
	metrics = app_checks->read_metrics(ml);
	EXPECT_EQ(0, metrics.size());
}
