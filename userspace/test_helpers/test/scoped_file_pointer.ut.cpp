/**
 * @file
 *
 * Unit tests for scoped_file_pointer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_file_pointer.h"
#include <gtest.h>

using test_helpers::scoped_file_pointer;

/**
 * Ensure that the constructor, when given a valid filename and valid mode,
 * does not throw any exceptions.
 */
TEST(scoped_file_pointer_test, valid_filename)
{
	const std::string filename = "/dev/null";
	const std::string mode = "w";

	ASSERT_NO_THROW({
		scoped_file_pointer sfp(filename, mode);
	});
}

/**
 * Ensure that the constructor, when given an invalid filename, throws a
 * std::runtime_error.
 */
TEST(scoped_file_pointer_test, invalid_filename_throws_exception)
{
	const std::string filename = "";
	const std::string mode = "taco";

	ASSERT_THROW({
		scoped_file_pointer sfp(filename, mode);
	}, std::runtime_error);
}

/**
 * Ensure that when a scoped_file_pointer is successfully constructed, that
 * get() returns non-nullptr.
 */
TEST(scoped_file_pointer_test, get)
{
	const std::string filename = "/dev/null";
	const std::string mode = "w";
	scoped_file_pointer sfp(filename, mode);

	ASSERT_NE(sfp.get(), nullptr);
}
