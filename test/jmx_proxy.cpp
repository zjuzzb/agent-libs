//
// Created by Luca Marturana on 05/05/15.
//

#include <gtest.h>
#include "sys_call_test.h"
#include "jmx_proxy.h"

class jmx_proxy_f : public ::testing::Test {
protected:
	virtual void SetUp() {
		devnull = fopen("/dev/null", "w");
		ASSERT_TRUE(devnull != NULL);
	}

	virtual void TearDown() {
		fclose(devnull);
		if(json_file)
		{
			fclose(json_file);
		}
		jmx.reset();
	}

	void use_json(const char *json)
	{
		string resource("resources/");
		resource += json;
		json_file = fopen(resource.c_str(), "r");
		ASSERT_TRUE(json_file != NULL);
		jmx.reset(new jmx_proxy(make_pair(devnull, json_file)));
	}

	FILE* devnull;
	FILE* json_file;
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