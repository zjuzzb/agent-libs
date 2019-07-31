/**
 * @file
 *
 * Unit test to validate the file_rest_registry class
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

#include <rest_util.h> // librest
#include <file_rest_registry.h> // dragent
#include <scoped_temp_file.h> // test_helpers
#include <fstream>
#include <gtest.h>

using namespace dragent;
using namespace test_helpers;

TEST(file_rest_registry_test, text_file)
{
	std::string expected = "HIJKLMN";

	scoped_temp_file file1("abcdefg");
	scoped_temp_file file2(expected);
	scoped_temp_file file3("opqrstu");

	file_rest_registry helper({file1.get_filename(),
		file2.get_filename(),
		file3.get_filename()});

	ASSERT_LE(3, helper.get_file_name_list().size());

	std::string content = helper.get_content_as_string(librest::post_last_slash(file2.get_filename()));

	ASSERT_FALSE(content.empty());
	ASSERT_EQ(expected, content);
}
