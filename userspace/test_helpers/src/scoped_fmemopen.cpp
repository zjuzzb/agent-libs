/**
 * @file
 *
 * Implementation of scoped_fmemopen.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_fmemopen.h"
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace test_helpers
{

scoped_fmemopen::scoped_fmemopen(const size_t buffer_size,
	                         const std::string& mode,
	                         const std::string& initial_state):
	m_buffer(buffer_size + 1), // + 1 for terminator
	m_file(fmemopen(m_buffer.data(), m_buffer.capacity(), mode.c_str()))
{
	set_buffer_content(initial_state);
}

FILE* scoped_fmemopen::get_file()
{
	return m_file.get();
}

std::string scoped_fmemopen::get_buffer_content() const
{
	// Make sure anything written to the stream has hit the buffer
	if(m_file.get() != nullptr)
	{
		fflush(m_file.get());
	}

	return std::string(m_buffer.data());
}

void scoped_fmemopen::set_buffer_content(const std::string& content)
{
	m_buffer.clear();
	m_buffer.resize(m_buffer.capacity(), '\0');

	// capacity() - 1 to omit terminator
	for(size_t i = 0; i < std::min(content.length(), m_buffer.capacity() - 1); ++i)
	{
		m_buffer[i] = content[i];
	}
}

} // namespace test_helpers
