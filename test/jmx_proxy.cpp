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
		string jsondata;
		json_file >> jsondata;

		m_inqueue->send(jsondata);
	}

	unique_ptr<posix_queue> m_inqueue;
	unique_ptr<jmx_proxy> jmx;
};

TEST_F(jmx_proxy_f, test_read_ok)
{
	use_json("jmx_ok.json");
	auto metrics = jmx->read_metrics();
	EXPECT_EQ(2U, metrics.size());
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
	EXPECT_NO_THROW(jmx->read_metrics(););
}

TEST(jmx_attribute, test_infinite_values)
{
	Json::Value value;
	Json::Reader reader;
	ASSERT_TRUE(reader.parse("{\"name\":\"Value\",\"value\":\"-Infinity\",\"type\":2,\"scale\":0,\"unit\":0}", value, false));
	java_bean_attribute attribute(value);
	EXPECT_EQ(0, attribute.value());
}

TEST(jmx_bean, test_filters)
{
	Json::Value jmx;
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
			"\"isWriteable\" : \"false \","
		  "}, {"
			"\"name\" : \"NumberOfRelationshipIdsInUse\","
			"\"value\" : 1,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false \","
		  "}, {"
			"\"name\" : \"NumberOfPropertyIdsInUse\","
			"\"value\" : 19078,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false \","
		  "}, {"
			"\"name\" : \"NumberOfRelationshipTypeIdsInUse\","
			"\"value\" : 0,"
			"\"isReadable\" : \"true\","
			"\"type\" : \"long\","
			"\"isWriteable\" : \"false \","
		  "} ],"
		  "\"url\" : \"org.neo4j/instance%3Dkernel%230%2Cname%3DPrimitive+count\""
		"}", jmx, true)
	);
	metrics_filter_vec f({{"NumberOfRelationship*", true}, {"NumberOfProperty*", false}});
	metric_limits::sptr_t ml(new metric_limits(f));
	java_bean jb(jmx, ml);
	ASSERT_EQ(3u, jb.attributes().size());
	ASSERT_EQ(4u, ml->cached());
	ASSERT_TRUE(ml->has("NumberOfNodeIdsInUse"));
	ASSERT_TRUE(ml->has("NumberOfRelationshipIdsInUse"));
	ASSERT_TRUE(ml->has("NumberOfPropertyIdsInUse"));
	ASSERT_TRUE(ml->has("NumberOfRelationshipTypeIdsInUse"));
}
