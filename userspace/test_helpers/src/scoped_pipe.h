/**
 * @file
 *
 * Interface to scoped_pipe -- a UT helper for creating and managing pipes
 * that live for the duration of the scope_pipe object.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <memory>

namespace test_helpers
{

class scoped_file_descriptor;

/**
 * A scoped_pipe wraps the pipe() system call and exposes two scoped file
 * descriptors corresponding to the read- and write-ends of the pipe.
 */
class scoped_pipe
{
public:
	/**
	 * Creates a new pipe and initializes this scoped_pipe with its
	 * file descriptors.
	 *
	 * @throws std::runtime_error if the pipe system call fails.
	 */
	scoped_pipe();

	/** Returns a reference to the read-end of the pipe. */
	scoped_file_descriptor& read_end();

	/** Returns a reference to the write-end of the pipe. */
	scoped_file_descriptor& write_end();

	/** Close both the read- and write-ends of the pipe. */
	void close();

private:
	std::unique_ptr<scoped_file_descriptor> m_read_end;
	std::unique_ptr<scoped_file_descriptor> m_write_end;
};

}
