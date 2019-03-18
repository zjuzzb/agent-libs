/**
 * @file
 *
 * Interface to scoped_file_descriptor -- an RAII wrapper over file descriptor
 * managmement.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

namespace test_helpers
{

/**
 * Wraps a file descriptor for the lifetime of the object, and closes the
 * file descriptor (if not already closed) when destroyed.
 */
class scoped_file_descriptor
{
public:
	scoped_file_descriptor(int fd);
	~scoped_file_descriptor();

	int get_fd() const;
	bool is_valid() const;
	void close();

private:
	int m_fd;
	bool m_closed;
};

}
