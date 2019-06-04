/**
 * @file
 *
 * Unit tests for rest_exception.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_exception.h"
#include <gtest.h>

using namespace librest;

/**
 * Ensure that a rest_exception with the default code is in the expected
 * initial state.
 */
TEST(rest_exception_test, initial_state)
{
	const std::string message = "my message";

	rest_exception ex(message);

	ASSERT_EQ(message, std::string(ex.what()));
	ASSERT_EQ(rest_exception::DEFAULT_CODE, ex.get_code());
}

/**
 * Ensure that a rest_exception with a custom code is in the expected
 * initial state.
 */
TEST(rest_exception_test, custom_code)
{
	const std::string message = "my message";
	const int code = 404;

	rest_exception ex(message, code);

	ASSERT_EQ(message, std::string(ex.what()));
	ASSERT_EQ(code, ex.get_code());
}
