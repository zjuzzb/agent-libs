/**
 * @file
 *
 * In-build unit test for scoped_file_descriptor.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_file_descriptor.h"
#include <gtest.h>

TEST(scoped_file_descriptor_test, bad_file_descriptor_not_valid)
{
	test_helpers::scoped_file_descriptor  fd(-1);

	ASSERT_EQ(-1, fd.get_fd());
	ASSERT_FALSE(fd.is_valid());

	// close should do no harm
	fd.close();
}

TEST(scoped_file_descriptor_test, good_file_descriptor)
{
	int pipe_fds[2] = {};

	ASSERT_EQ(0, pipe(pipe_fds));

	{
		test_helpers::scoped_file_descriptor fd1(pipe_fds[0]);
		test_helpers::scoped_file_descriptor fd2(pipe_fds[1]);

		ASSERT_TRUE(fd1.is_valid());
		ASSERT_TRUE(fd2.is_valid());

		ASSERT_EQ(pipe_fds[0], fd1.get_fd());
		ASSERT_EQ(pipe_fds[1], fd2.get_fd());

		// Explicitly close pipe_fds[0], let the destructor close
		// pipe_fds[1]
		fd1.close();
	}

	// Since the helper closed the file descriptor, trying to close it
	// now should fail.  Note that this assumes no other thread in this
	// test opened a file descriptor between the time the fd was closed
	// above and our attempt to close it here.
	errno = 0;
	const int rc1 = close(pipe_fds[0]);
	const int err1 = errno;

	errno = 0;
	const int rc2 = close(pipe_fds[1]);
	const int err2 = errno;

	ASSERT_EQ(-1, rc1);
	ASSERT_EQ(EBADF, err1);

	ASSERT_EQ(-1, rc2);
	ASSERT_EQ(EBADF, err2);
}
