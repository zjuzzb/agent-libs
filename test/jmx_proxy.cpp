//
// Created by Luca Marturana on 05/05/15.
//

#include <gtest.h>
#include "sys_call_test.h"
#include "jmx_proxy.h"
#include "posix_queue.h"
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
	EXPECT_EQ(2, metrics.second.size());
	EXPECT_EQ(1430840190367187500, metrics.first);
}

TEST_F(jmx_proxy_f, test_read_fail)
{
	use_json("jmx_fail.json");
	auto metrics = jmx->read_metrics();
	EXPECT_EQ(0, metrics.second.size());
	EXPECT_EQ(0, metrics.first);
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
	reader.parse("{\"name\":\"Value\",\"value\":\"-Infinity\",\"type\":2,\"scale\":0,\"unit\":0}", value, false);
	java_bean_attribute attribute(value);
	EXPECT_EQ(0, attribute.value());
}