#include <gtest.h>
#include "sys_call_test.h"
#include "app_checks.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include "analyzer.h"
#include "draios.pb.h"
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

TEST_F(app_checks_proxy_f, limits)
{
	use_json("app_checks_ok.json");
	auto metrics = app_checks->read_metrics(nullptr);
	ASSERT_EQ(2U, metrics.size());

	draiosproto::metrics proto;
	draiosproto::program* prog = proto.add_programs();
	draiosproto::process* proc = prog->mutable_procinfo();
	auto app = proc->mutable_protos()->mutable_app();
	auto app_checks_data = metrics[805].begin()->second;

	uint16_t app_checks_limit = 0;
	ASSERT_EQ(31U, app_checks_data.metrics().size());
	ASSERT_EQ(0, app->metrics().size());
	do
	{
		app_checks_data.to_protobuf(app, app_checks_limit);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(0, app->metrics().size());

	app_checks_limit = 1;
	ASSERT_EQ(31U, app_checks_data.metrics().size());
	ASSERT_EQ(0, app->metrics().size());
	do
	{
		app_checks_data.to_protobuf(app, app_checks_limit);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(1U, app->metrics().size());

	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data.metrics().size());
	app_checks_limit = 15;
	do
	{
		app_checks_data.to_protobuf(app, app_checks_limit);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(15, app->metrics().size());

	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data.metrics().size());
	app_checks_limit = 30;
	do
	{
		app_checks_data.to_protobuf(proc->mutable_protos()->mutable_app(), app_checks_limit);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(30U, app->metrics().size());

	// services are also populated into metrics
	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data.metrics().size());
	ASSERT_EQ(1U, app_checks_data.services().size());
	app_checks_limit = 32;
	do
	{
		app_checks_data.to_protobuf(proc->mutable_protos()->mutable_app(), app_checks_limit);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(32U, app->metrics().size());

	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data.metrics().size());
	ASSERT_EQ(1U, app_checks_data.services().size());
	app_checks_limit = 33;
	do
	{
		app_checks_data.to_protobuf(proc->mutable_protos()->mutable_app(), app_checks_limit);
	} while(app_checks_limit > 1);
	ASSERT_EQ(1, app_checks_limit);
	EXPECT_EQ(32U, app->metrics().size());
/*
	// test the function determining whether to
	// log excess metrics
	g_logger.set_severity(sinsp_logger::SEV_DEBUG);
	// make sure we get the default forced true multiple times,
	// until we reset the flag to switch to timed operation
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics());
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics());
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics());
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics());
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics());
	g_logger.set_severity(sinsp_logger::SEV_INFO);
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	g_logger.set_severity(sinsp_logger::SEV_DEBUG);
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics());
	sinsp_analyzer::m_force_excess_metric_log = false;
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	// now make sure timed operation works as expected
	sleep(2);
	// default is 300 seconds, so this must be false
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	// but 1 second interval must pass
	EXPECT_TRUE(sinsp_analyzer::log_excess_metrics(1));

	// make sure lower log level is no-op
	g_logger.set_severity(sinsp_logger::SEV_INFO);
	sinsp_analyzer::m_force_excess_metric_log = true;
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	sinsp_analyzer::m_force_excess_metric_log = false;
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	sleep(2);
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics());
	EXPECT_FALSE(sinsp_analyzer::log_excess_metrics(1));*/
}
