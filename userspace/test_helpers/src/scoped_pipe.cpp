/**
 * @file
 *
 * Implementation of scoped_pipe -- a UT helper for creating and managing pipes
 * that live for the duration of the scope_pipe object.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_pipe.h"
#include "scoped_file_descriptor.h"

#include <cstring>
#include <exception>
#include <sstream>
#include <unistd.h>

using namespace test_helpers;

scoped_pipe::scoped_pipe():
	m_read_end(),
	m_write_end()
{
	int fds[2] = {};

	if(pipe(fds) < 0)
	{
		std::stringstream out;

		out << "scoped_pipe: Failed to create pipe, error: "
		    << strerror(errno);

		throw std::runtime_error(out.str());
	}

	m_read_end.reset(new scoped_file_descriptor(fds[0]));
	m_write_end.reset(new scoped_file_descriptor(fds[1]));
}

scoped_file_descriptor& scoped_pipe::read_end()
{
	return *m_read_end.get();
}

scoped_file_descriptor& scoped_pipe::write_end()
{
	return *m_write_end.get();
}

void scoped_pipe::close()
{
	m_read_end->close();
	m_write_end->close();
}
