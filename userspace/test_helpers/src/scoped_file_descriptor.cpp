/**
 * @file
 *
 * Implementation of scoped_file_descriptor -- an RAII wrapper over file
 * descriptor managmement.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_file_descriptor.h"

#include <unistd.h>

using namespace test_helpers;

scoped_file_descriptor::scoped_file_descriptor(const int fd):
	m_fd(fd),
	m_closed(false)
{ }

scoped_file_descriptor::~scoped_file_descriptor()
{
	close();
}

int scoped_file_descriptor::get_fd() const
{
	return m_fd;
}

bool scoped_file_descriptor::is_valid() const
{
	return m_fd >= 0;
}

void scoped_file_descriptor::close()
{
	if(is_valid() && !m_closed)
	{
		::close(m_fd);
		m_fd = -1;
	}
	m_closed = true;
}
