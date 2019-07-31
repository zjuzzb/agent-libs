/**
 * @file
 *
 * Unit tests for rest_util.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_util.h"
#include <gtest.h>

using namespace librest;

TEST(rest_util, post_last_slash)
{
	std::string result = post_last_slash("no_slash_here");
	ASSERT_EQ("", result);

	result = post_last_slash("/");
	ASSERT_EQ("", result);

	result = post_last_slash("/home");
	ASSERT_EQ("home", result);

	result = post_last_slash("home/star");
	ASSERT_EQ("star", result);

	result = post_last_slash("home/star/");
	ASSERT_EQ("", result);

	result = post_last_slash("/home/star/runner");
	ASSERT_EQ("runner", result);
}
