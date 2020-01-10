#include <sys/time.h>
#include <sys/resource.h>

#include <gtest.h>
#include "sys_call_test.h"
#include "app_checks_proxy.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include "analyzer.h"
#include "draios.pb.h"
#include <fstream>
#include "third-party/jsoncpp/json/json.h"

class app_checks_proxy_f : public ::testing::Test {
protected:
	virtual void SetUp() {
		struct rlimit msgqueue_rlimits = {
			.rlim_cur = posix_queue::min_msgqueue_limit(),
			.rlim_max = posix_queue::min_msgqueue_limit()
		};
		if(setrlimit(RLIMIT_MSGQUEUE, &msgqueue_rlimits) != 0)
		{
			std::cerr << "Cannot set msgqueue limits: " << strerror(errno) << '\n';
		}

		m_inqueue = make_unique<posix_queue>("/sdc_app_checks_out", posix_queue::SEND, 1);
	}

	virtual void TearDown() {
		m_inqueue.reset();
	}

	void use_json(const char *json)
	{
		const std::string header{0x01, 0x00, 0x00, 0x00, 0x00};
		std::string jsondata;
		std::string resource("resources/");
		resource += json;
		std::ifstream json_file(resource);
		getline(json_file, jsondata);
		m_inqueue->send(header + jsondata);
	}

	std::unique_ptr<posix_queue> m_inqueue;
};

TEST_F(app_checks_proxy_f, read_ok)
{
	auto app_checks = make_unique<app_checks_proxy>(nullptr, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	const auto& metrics = app_checks->get_all_metrics().lock();
	EXPECT_EQ(2U, metrics->size());
}

std::string print(const app_checks_proxy_interface::raw_metric_map_t& metrics)
{
	std::stringstream out;
	//std::unordered_map<int, std::map<std::string, app_check_data>>
	for(const auto& app : metrics)
	{
		int metric = 0, services = 0;
		out << app.first << std::endl;
		for(const auto& acd : app.second)
		{
			out << '\t' << acd.first << std::endl;
			for(const auto& m : acd.second->metrics())
			{
				out << "\t\t" << m.name() << std::endl;
				++metric;
			}
			for(const auto& d : acd.second->services())
			{
				out << "\t\t" << d.name() << std::endl;
				++services;
			}
			out << acd.second->total_metrics() << " total metrics" << std::endl;

		}
		out << "-------" << std::endl;
		out << metric << " metrics" << std::endl;
		out << services << " services" << std::endl;
	}
	return out.str();
}

template <typename T>
bool has(const T& svcs, const std::string& name)
{
	for(const auto& s : svcs)
	{
		if(s.name() == name)
		{
			return true;
		}
	}
	return false;
}

TEST_F(app_checks_proxy_f, no_filters)
{
	auto app_checks = make_unique<app_checks_proxy>(nullptr, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	auto metrics(std::move(app_checks->get_all_metrics().lock()));
	ASSERT_EQ(2U, metrics->size());
	//print(metrics);
	EXPECT_EQ(0u, metrics->at(2115).begin()->second->metrics().size());
	EXPECT_EQ(1u, metrics->at(2115).begin()->second->services().size());
	EXPECT_EQ(31u, metrics->at(805).begin()->second->metrics().size());
	EXPECT_EQ(1u, metrics->at(805).begin()->second->services().size());
	app_check_data::metrics_t metric_list = metrics->at(805).begin()->second->metrics();
	EXPECT_TRUE(has(metric_list, "redis.keys.evicted"));
	EXPECT_TRUE(has(metric_list, "redis.net.slaves"));
	EXPECT_TRUE(has(metric_list, "redis.cpu.sys"));
	EXPECT_TRUE(has(metric_list, "redis.keys.expired"));
	EXPECT_TRUE(has(metric_list, "redis.rdb.last_bgsave_time"));
	app_check_data::services_t service_list = metrics->at(805).begin()->second->services();
	EXPECT_TRUE(has(service_list, "redis.can_connect"));
}

TEST_F(app_checks_proxy_f, filters1)
{
	filter_vec_t f({{"*", false}, {"*.can_connect", true}});
	metric_limits::sptr_t ml(new metric_limits(std::move(f)));
	auto app_checks = make_unique<app_checks_proxy>(ml, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	auto metrics(std::move(app_checks->get_all_metrics().lock()));

	ASSERT_EQ(2U, metrics->size()) << print(*metrics);
	app_check_data::metrics_t metric_list = metrics->at(805).begin()->second->metrics();
	EXPECT_EQ(0U, metric_list.size());
	app_check_data::services_t service_list = metrics->at(805).begin()->second->services();
	EXPECT_EQ(0U, service_list.size());
	service_list = metrics->at(2115).begin()->second->services();
	EXPECT_EQ(0U, service_list.size());
}

TEST_F(app_checks_proxy_f, filters2)
{
	filter_vec_t f = {{"redis.mem.*", true}, {"*.can_connect", true}, {"*", false}};
	metric_limits::sptr_t ml(new metric_limits(std::move(f)));
	auto app_checks = make_unique<app_checks_proxy>(ml, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	auto metrics(std::move(app_checks->get_all_metrics().lock()));

	ASSERT_EQ(2U, metrics->size()) << print(*metrics);
	app_check_data::metrics_t metric_list = metrics->at(805).begin()->second->metrics();
	EXPECT_EQ(5U, metric_list.size()) << print(*metrics);
	app_check_data::services_t service_list = metrics->at(805).begin()->second->services();
	EXPECT_EQ(1U, service_list.size());
	service_list = metrics->at(2115).begin()->second->services();
	EXPECT_EQ(1U, service_list.size());

	metric_list = metrics->at(2115).begin()->second->metrics();
	EXPECT_EQ(0u, metric_list.size());
	service_list = metrics->at(2115).begin()->second->services();
	EXPECT_EQ(1u, service_list.size());
	EXPECT_TRUE(has(service_list, "nginx.can_connect"));

	metric_list = metrics->at(805).begin()->second->metrics();
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
	service_list = metrics->at(805).begin()->second->services();
	EXPECT_EQ(1u, service_list.size());
	EXPECT_TRUE(has(service_list, "redis.can_connect"));
}

TEST_F(app_checks_proxy_f, filters3)
{
	filter_vec_t f = {{"*", false}, {"redis.mem.*", true}, {"*.can_connect", true}};
	metric_limits::sptr_t ml(new metric_limits(std::move(f)));
	auto app_checks = make_unique<app_checks_proxy>(ml, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	auto metrics(std::move(app_checks->get_all_metrics().lock()));

	ASSERT_EQ(2U, metrics->size()) << print(*metrics);
	app_check_data::metrics_t metric_list = metrics->at(805).begin()->second->metrics();
	EXPECT_EQ(0U, metric_list.size());
	app_check_data::services_t service_list = metrics->at(805).begin()->second->services();
	EXPECT_EQ(0U, service_list.size());
	service_list = metrics->at(2115).begin()->second->services();
	EXPECT_EQ(0U, service_list.size());
}

TEST_F(app_checks_proxy_f, filters4)
{
	filter_vec_t f = {{"*", false}};
	metric_limits::sptr_t ml(new metric_limits(std::move(f)));
	auto app_checks = make_unique<app_checks_proxy>(ml, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	auto metrics(std::move(app_checks->get_all_metrics().lock()));

	ASSERT_EQ(2U, metrics->size()) << print(*metrics);
	app_check_data::metrics_t metric_list = metrics->at(805).begin()->second->metrics();
	EXPECT_EQ(0U, metric_list.size());
	app_check_data::services_t service_list = metrics->at(805).begin()->second->services();
	EXPECT_EQ(0U, service_list.size());
	service_list = metrics->at(2115).begin()->second->services();
	EXPECT_EQ(0U, service_list.size());
}

TEST_F(app_checks_proxy_f, limits)
{
	auto app_checks = make_unique<app_checks_proxy>(nullptr, false);
	use_json("app_checks_ok.json");
	app_checks->refresh_metrics(time(nullptr), 1);
	auto metrics(std::move(app_checks->get_all_metrics().lock()));
	ASSERT_EQ(2U, metrics->size());

	draiosproto::metrics proto;
	draiosproto::program* prog = proto.add_programs();
	draiosproto::process* proc = prog->mutable_procinfo();
	auto app = proc->mutable_protos()->mutable_app();
	auto app_checks_data = metrics->at(805).begin()->second;

	unsigned int app_checks_limit = 0;
	ASSERT_EQ(31U, app_checks_data->metrics().size());
	ASSERT_EQ(0, app->metrics().size());
	do
	{
		app_checks_data->to_protobuf(app, app_checks_limit, 0);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(0, app->metrics().size());

	app_checks_limit = 1;
	ASSERT_EQ(31U, app_checks_data->metrics().size());
	ASSERT_EQ(0, app->metrics().size());
	do
	{
		app_checks_data->to_protobuf(app, app_checks_limit, 0);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(1, app->metrics().size());

	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data->metrics().size());
	app_checks_limit = 15;
	do
	{
		app_checks_data->to_protobuf(app, app_checks_limit, 0);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(15, app->metrics().size());

	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data->metrics().size());
	app_checks_limit = 30;
	do
	{
		app_checks_data->to_protobuf(app, app_checks_limit, 0);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(30, app->metrics().size());

	// services are also populated into metrics
	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data->metrics().size());
	ASSERT_EQ(1U, app_checks_data->services().size());
	app_checks_limit = 32;
	do
	{
		app_checks_data->to_protobuf(app, app_checks_limit, 0);
	} while(app_checks_limit);
	ASSERT_EQ(0, app_checks_limit);
	EXPECT_EQ(32, app->metrics().size());

	app->clear_metrics();
	ASSERT_EQ(0, app->metrics().size());
	ASSERT_EQ(31U, app_checks_data->metrics().size());
	ASSERT_EQ(1U, app_checks_data->services().size());
	app_checks_limit = 33;
	do
	{
		app_checks_data->to_protobuf(app, app_checks_limit, 0);
	} while(app_checks_limit > 1);
	ASSERT_EQ(1, app_checks_limit);
	EXPECT_EQ(32, app->metrics().size());
}
