/**
 * @file
 *
 * Unit tests for scoped_stdout_capture.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_stdout_capture.h"
#include <gtest.h>

TEST(scoped_stdout_capture_test, basic)
{
	test_helpers::scoped_stdout_capture capture;
	printf("can't stop");
	printf("won't stop");
	printf("get guap");
	printf("ten white toes in my Tori flip flops");

	ASSERT_EQ(std::string("can't stopwon't stopget guapten white toes in my Tori flip flops"),
		  capture.get());

	ASSERT_TRUE(capture.find("guap"));
	ASSERT_FALSE(capture.find("guac"));
	ASSERT_TRUE(capture.find("stop"));
}

TEST(scoped_stdout_capture_test, teardown)
{
	test_helpers::scoped_stdout_capture capture1;
	printf("hello");
	{
		test_helpers::scoped_stdout_capture capture2;
		printf("goodbye");
	}

	printf("world");

	ASSERT_EQ(std::string("helloworld"), capture1.get());
}
