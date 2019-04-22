/**
 * @file
 *
 * Unit tests for scoped_temp_directory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

#include "scoped_temp_directory.h"
#include "scoped_file_descriptor.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <gtest.h>

TEST(scoped_temp_directory_test, created_removed_successfully)
{
	std::string directory;

	{
		test_helpers::scoped_temp_directory temp_directory;

		ASSERT_NE(temp_directory.get_directory(), std::string());

		directory = temp_directory.get_directory();

		// Make sure the directory exists and is a ... directory
		struct stat statbuf = {};
		ASSERT_EQ(0, stat(directory.c_str(), &statbuf));
		ASSERT_TRUE(S_ISDIR(statbuf.st_mode));

		// Create a file "someFile.txt" in the directory
		const std::string filename = directory + "/" + "someFile.txt";
		test_helpers::scoped_file_descriptor fd(open(filename.c_str(),
		                                             O_CREAT,
		                                             0600));
		ASSERT_TRUE(fd.is_valid());

		// Create a subdirectory "somedir" in the directory
		const std::string subdir = directory + "/" + "somedir";
		ASSERT_EQ(0, mkdir(subdir.c_str(), 0700));
	}

	// Make sure that the directory no longer exists
	struct stat statbuf = {};

	errno = 0;
	const int rc = stat(directory.c_str(), &statbuf);
	const int err = errno;

	ASSERT_EQ(-1, rc);
	ASSERT_EQ(ENOENT, err);
}
