/**
 * @file
 *
 * Unit tests for scoped_temp_file.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_temp_file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <gtest.h>

TEST(scoped_temp_file_test, created_successfully)
{
	std::string filename;

	{
		test_helpers::scoped_temp_file temp_file;

		ASSERT_NE(temp_file.get_filename(), std::string());
		ASSERT_TRUE(temp_file.created_successfully());

		filename = temp_file.get_filename();

		// We should be able to open the file -- the constructor should
		// have created it.
		errno = 0;
		const int fd = open(filename.c_str(), O_RDONLY);
		ASSERT_EQ(0, errno);
		ASSERT_NE(fd, -1);
		close(fd);
	}

	const int fd = open(filename.c_str(), O_RDONLY);
	ASSERT_EQ(ENOENT, errno);
	ASSERT_EQ(-1, fd);
}

TEST(scoped_temp_file_test, file_with_initial_content)
{
	std::string expected = "Never trust a bald barber. He has no respect for your hair.";

       test_helpers::scoped_temp_file temp_file(expected);
	std::ifstream in(temp_file.get_filename());

	std::string content((std::istreambuf_iterator<char>(in)),
			    std::istreambuf_iterator<char>());

	ASSERT_EQ(expected, content);
}

TEST(scoped_temp_file_test, file_with_extension)
{
	std::string expected = "json";
	test_helpers::scoped_temp_file temp_file("qwerty", expected);
	std::string found = temp_file.get_filename().substr(temp_file.get_filename().length() - expected.length());
	ASSERT_EQ(expected, found);
}
