//
// Created by Luca Marturana on 05/05/15.
//

#include <gtest.h>
#include "sys_call_test.h"
#include "jmx_proxy.h"
#include "posix_queue.h"
#include "metric_limits.h"
#include <fstream>
#include "third-party/jsoncpp/json/json.h"

class jmx_proxy_f : public ::testing::Test {
protected:
	virtual void SetUp() {
		m_inqueue = make_unique<posix_queue>("/sdc_sdjagent_out", posix_queue::SEND, 1);
		jmx = make_unique<jmx_proxy>();
	}

	virtual void TearDown() {
		m_inqueue.reset();
		jmx.reset();
	}

	void use_json(const char *json)
	{
		string resource("resources/");
		resource += json;
		ifstream json_file(resource);
		m_jsondata.clear();
		json_file >> m_jsondata;
		m_inqueue->send(m_jsondata);
	}

	unique_ptr<posix_queue> m_inqueue;
	unique_ptr<jmx_proxy> jmx;
	string m_jsondata;
};

TEST_F(jmx_proxy_f, test_read_ok)
{
	use_json("jmx_ok.json");
	auto metrics = jmx->read_metrics();
	EXPECT_EQ(2U, metrics.size());
	auto it = metrics.find(9675);
	ASSERT_NE(it, metrics.end());
	EXPECT_EQ(10u, it->second.total_metrics());
	it = metrics.find(8951);
	ASSERT_NE(it, metrics.end());
	EXPECT_EQ(91u, it->second.total_metrics());
}

TEST_F(jmx_proxy_f, test_read_fail)
{
	use_json("jmx_fail.json");
	auto metrics = jmx->read_metrics();
	EXPECT_EQ(0U, metrics.size());
}

TEST_F(jmx_proxy_f, test_read_segv)
{
	use_json("jmx_segfault.json");
	EXPECT_NO_THROW(jmx->read_metrics(););
}

TEST_F(jmx_proxy_f, test_wrong_object)
{
	use_json("jmx_wrong_object.json");
	EXPECT_NO_THROW(jmx->read_metrics());
}

TEST(jmx_attribute, test_infinite_values)
{
	Json::Value value;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse("{\"name\":\"Value\",\"value\":\"-Infinity\",\"type\":2,\"scale\":0,\"unit\":0}", value, false));
	java_bean_attribute attribute(value);
	EXPECT_EQ(0, attribute.value());
}

TEST(jmx_bean, test_filter)
{
	Json::Value jv;
	Json::Reader reader;
	ASSERT_TRUE(
		reader.parse(
		"{"
		  "\"name\" : \"org.neo4j:instance=kernel#0,name=Primitive count\","
		  "\"attributes\" : [ {"
			"\"name\" : \"NumberOfNodeIdsInUse\","
			"\"value\" : 24117,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false\""
		  "}, {"
			"\"name\" : \"NumberOfRelationshipIdsInUse\","
			"\"value\" : 1,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false\""
		  "}, {"
			"\"name\" : \"NumberOfPropertyIdsInUse\","
			"\"value\" : 19078,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false\""
		  "}, {"
			"\"name\" : \"NumberOfRelationshipTypeIdsInUse\","
			"\"value\" : 0,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false\""
		  "} ],"
		  "\"url\" : \"org.neo4j/instance%3Dkernel%230%2Cname%3DPrimitive+count\""
		"}", jv, true)
	);
	filter_vec_t f = {{"NumberOfRelationship*", true}, {"NumberOfProperty*", false}};
	metric_limits::sptr_t ml(new metric_limits(f, 4u));
	java_bean jb(jv, ml);
	ASSERT_EQ(3u, jb.attributes().size());
	ASSERT_EQ(4u, ml->cached());
	ASSERT_TRUE(ml->has("NumberOfNodeIdsInUse"));
	ASSERT_TRUE(ml->has("NumberOfRelationshipIdsInUse"));
	ASSERT_TRUE(ml->has("NumberOfPropertyIdsInUse"));
	ASSERT_TRUE(ml->has("NumberOfRelationshipTypeIdsInUse"));
}

jmx_proxy::process_map_t run_filtering(unique_ptr<jmx_proxy>& jmx, const filter_vec_t& f)
{
	metric_limits::sptr_t ml(new metric_limits(f));
	jmx_proxy::process_map_t metrics = jmx->read_metrics(ml);
	return metrics;
}

bool find_attribute(const java_bean::attribute_list_t& attrs, const std::string& name, const std::string& alias)
{
	for(auto a : attrs)
	{
		if(a.name() == name && a.alias() == alias)
		{
			return true;
		}
	}
	return false;
}

void print_metrics(const jmx_proxy::process_map_t& metrics)
{
	int bc = 0, tbc = 0, ac = 0, tac = 0, sac = 0, tsac = 0, total = 0;
	std::cout << "+++processes+++" << std::endl;
	for(auto met : metrics)
	{
		std::cout << met.second.name() << std::endl;
		std::cout << "\t+++beans+++" << std::endl;
		for(auto b : met.second.beans())
		{
			std::cout << "\t" << bc++ << ' ' << b.name() << std::endl;
			std::cout << "\t\t+++attributes+++" << std::endl;
			for(auto a : b.attributes())
			{
				std::cout << "\t\t" << ac++ << ' ' << a.name() << " (" << a.alias() << ')' << std::endl;
				if(a.subattributes().size())
				{
					std::cout << "\t\t\t+++subattributes+++" << std::endl;
					for(auto s : a.subattributes())
					{
						std::cout << "\t\t\t" << sac++ << ' ' << s.name() << std::endl;
					}
					std::cout << "\t\t\t---subattributes---" << std::endl;
					tsac += sac;
					total += sac;
					sac = 0;
				}
			}
			std::cout << "\t\t---attributes---" << std::endl;
			tac += ac;
			total += ac;
			ac = 0;
		}
		std::cout << "\t---beans---" << std::endl;
		tbc += bc;
		total += bc;
		bc = 0;
	}
	std::cout << "---processes---" << std::endl;
	std::cout << "procs=" << metrics.size() << ", beans=" << tbc << ", attributes="
			<< tac << ", subattributes=" << tsac << ", total=" << total << std::endl;
}

TEST_F(jmx_proxy_f, test_filters)
{
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());

	// Rule 1.
	// metric is included if neither name nor alias is found in the list
	filter_vec_t f({{"some*", false}, {"thing.*", false}});
	auto metrics = run_filtering(jmx, f);
	//print_metrics(metrics);
	EXPECT_EQ(2u, metrics.size());
	EXPECT_EQ(31u, metrics.begin()->second.beans().size());
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));
	// End Rule 1.

	// Rule 2.
	// if [alias OR name OR both] are found in the list, metric is included/excluded based on first found
	//
	// forbid alias
	f = {{"tomcat.servlet.request.*", false}, {"some*", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(2u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_FALSE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// allow alias
	f = {{"tomcat.servlet.request.*", true}, {"some*", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// forbid name
	f = {{"requestCount", false}, {"some*", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(2u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_FALSE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// allow name
	f = {{"requestCount", true}, {"some*", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// forbid alias, allow name
	f = {{"tomcat.servlet.request.*", false}, {"requestCount", true}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(2u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_FALSE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// allow alias, forbid name
	f = {{"tomcat.servlet.request.*", true}, {"requestCount", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// forbid name, allow alias
	f = {{"requestCount", false}, {"tomcat.servlet.request.*", true}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(2u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_FALSE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// allow name, forbid alias
	f = {{"requestCount", true}, {"tomcat.servlet.request.*", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// allow both
	f = {{"requestCount", true}, {"tomcat.servlet.request.*", true}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// allow both again, reversed
	f = {{"tomcat.servlet.request.*", true}, {"requestCount", true}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_TRUE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// forbid both
	f = {{"requestCount", false}, {"tomcat.servlet.request.*", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(2u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_FALSE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));

	// forbid both again, reversed
	f = {{"tomcat.servlet.request.*", false}, {"requestCount", false}, {"thing.*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(2u, metrics.begin()->second.beans().rbegin()->attributes().size());
	EXPECT_FALSE(find_attribute(metrics.begin()->second.beans().rbegin()->attributes(),
				"requestCount", "tomcat.servlet.request.count"));
	// End Rule 2.

	// forbid everything
	f = {{"*", false}};
	use_json("jmx_ok.json");
	ASSERT_TRUE(m_jsondata.size());
	metrics = run_filtering(jmx, f);
	EXPECT_EQ(0u, metrics.begin()->second.beans().size());

}

TEST_F(jmx_proxy_f, limits)
{
	use_json("jmx_ok.json");
	auto metrics = jmx->read_metrics();
	ASSERT_EQ(2U, metrics.size());

	draiosproto::metrics proto;
	draiosproto::program* prog = proto.add_programs();
	draiosproto::process* proc = prog->mutable_procinfo();
	auto app = proc->mutable_protos()->mutable_java();
	EXPECT_EQ(31u, metrics.begin()->second.beans().size());
	EXPECT_EQ(3u, metrics.begin()->second.beans().rbegin()->attributes().size());
	auto pid = metrics.begin()->second;// Tomcat process from JSON file
	
	EXPECT_EQ(91u, pid.total_metrics());
	unsigned limit = 3000;
	limit -= pid.to_protobuf(app, 1, limit, "process", JMX_METRICS_HARD_LIMIT_PER_PROC);
	ASSERT_TRUE(limit);

	EXPECT_EQ(31, app->beans().size());
	EXPECT_EQ(2, app->beans(0).attributes().size());
	EXPECT_EQ(3, app->beans(14).attributes().size());
	EXPECT_EQ(5, app->beans(22).attributes().size());
	EXPECT_EQ(3, app->beans(30).attributes().size());
	app->clear_beans();

	limit = 1;
	limit -= pid.to_protobuf(app, 1, limit, "process", JMX_METRICS_HARD_LIMIT_PER_PROC);

	ASSERT_EQ(0u, limit);
	EXPECT_EQ(1, app->beans().size());
	EXPECT_EQ(1, app->beans(0).attributes().size());
	app->clear_beans();

	limit = 2;
	limit -= pid.to_protobuf(app, 1, limit, "process", JMX_METRICS_HARD_LIMIT_PER_PROC);

	ASSERT_EQ(0u, limit);
	EXPECT_EQ(1, app->beans().size());
	EXPECT_EQ(2, app->beans(0).attributes().size());
	app->clear_beans();

	limit = 3;
	do
	{
		limit -= pid.to_protobuf(app, 1, limit, "process", JMX_METRICS_HARD_LIMIT_PER_PROC);
	} while (limit);

	ASSERT_EQ(0u, limit);
	EXPECT_EQ(2, app->beans().size());
	EXPECT_EQ(2, app->beans(0).attributes().size());
	EXPECT_EQ(1, app->beans(1).attributes().size());
}
