#include <gtest.h>
#include "json_query.h"

TEST(json_query, barebone)
{
	// barebone proper call sequence
	std::string json = "{\"foo\": \"bar\"}";
	std::string filter = ".|{baz: .foo}";
	jq_state* jq = jq_init();
	EXPECT_TRUE(jq != 0);
	EXPECT_TRUE(0 != jq_compile(jq, filter.c_str()));
	jv input = jv_parse_sized(json.c_str(), json.length());
	EXPECT_TRUE(jv_is_valid(input));
	jq_start(jq, input, 0);
	jv result = jq_next(jq);
	EXPECT_TRUE(jv_is_valid(result));
	jv_free(result);
	jq_teardown(&jq);
}

TEST(json_query, query)
{
	std::string json = "{\"foo\": \"bar\"}";
	std::string filter = ".|{\"baz\": .foo}";
	json_query jq;
	EXPECT_TRUE(jq.process(json, filter));
	EXPECT_TRUE(jq.get_error().empty());
	// call result() twice to ensure result is cached
	// and there's no inadvertent double-processing
	// and/or engine state corruption
	EXPECT_TRUE(jq.result() == "{\"baz\":\"bar\"}");
	EXPECT_TRUE(jq.result() == "{\"baz\":\"bar\"}");

	json = "\"foo\": \"bar}";
	filter = ".|{baz: .foo}";
	EXPECT_FALSE(jq.process(json, filter));
	EXPECT_FALSE(jq.get_error().empty());

	json = "[1,2,5,3,5,3,1,3]";
	filter = "unique";
	EXPECT_TRUE(jq.process(json, filter));
	EXPECT_TRUE(jq.get_error().empty());
	EXPECT_TRUE(jq.result() == "[1,2,3,5]");
	EXPECT_TRUE(jq.result() == "[1,2,3,5]");
}
