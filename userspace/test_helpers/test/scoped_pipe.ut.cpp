/**
 * @file
 *
 * Unit test for scoped_file_descriptor.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_pipe.h"
#include "scoped_file_descriptor.h"

#include <cstring>
#include <fcntl.h>
#include <gtest.h>
#include <unistd.h>
#include <vector>

namespace
{

/**
 * Ensure that that the given file descriptor is not open.
 */
void ensure_closed(const int fd)
{
	errno = 0;
	const int rc = fcntl(fd, F_GETFD);
	const int err = errno;

	ASSERT_EQ(-1, rc);
	ASSERT_EQ(EBADF, err);
}

} // end namespace

/**
 * Ensure that client code can write to the write-end, and read what was written
 * from the read-end.
 */
TEST(scoped_pipe_test, read_write)
{
	test_helpers::scoped_pipe pipe;

	ASSERT_TRUE(pipe.read_end().is_valid());
	ASSERT_TRUE(pipe.write_end().is_valid());

	const char* const msg = "hello";
	std::vector<char> buffer(strlen(msg) + 1);

	ASSERT_TRUE(write(pipe.write_end().get_fd(), msg, strlen(msg)) >= 0);
	ASSERT_TRUE(read(pipe.read_end().get_fd(), buffer.data(), buffer.size() - 1) >= 0);

	ASSERT_STREQ(msg, buffer.data());
}

/**
 * Ensure that a scoped_pipe closes its file descriptors on destruction.
 */
TEST(scoped_pipe_test, close_on_destruction)
{
	int read_end = -1;
	int write_end = -1;

	{
		test_helpers::scoped_pipe pipe;

		ASSERT_TRUE(pipe.read_end().is_valid());
		ASSERT_TRUE(pipe.write_end().is_valid());

		read_end = pipe.read_end().get_fd();
		write_end = pipe.write_end().get_fd();
	}

	ensure_closed(read_end);
	ensure_closed(write_end);
}

/**
 * Ensure that close closes both the read- and write-ends of the pipe.
 */
TEST(scoped_pipe_test, close_on_close)
{
	test_helpers::scoped_pipe pipe;

	ASSERT_TRUE(pipe.read_end().is_valid());
	ASSERT_TRUE(pipe.write_end().is_valid());

	const int read_end = pipe.read_end().get_fd();
	const int write_end = pipe.write_end().get_fd();

	pipe.close();

	ensure_closed(read_end);
	ensure_closed(write_end);
}
