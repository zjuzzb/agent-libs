/**
 * @file
 *
 * Implementation of scoped_file_pointer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_file_pointer.h"
#include <cstdio>
#include <stdexcept>
#include <string>

namespace test_helpers
{

scoped_file_pointer::scoped_file_pointer(const std::string& filename,
                                         const std::string& mode):
	m_file(fopen(filename.c_str(), mode.c_str()))
{
	if(m_file == nullptr)
	{
		throw std::runtime_error("Failed to open " + filename +
		                         " with mode " + mode);
	}
}

scoped_file_pointer::scoped_file_pointer(FILE* const file):
	m_file(file)
{ }

scoped_file_pointer::~scoped_file_pointer()
{
	if(m_file != nullptr)
	{
		fclose(m_file);
	}
}

FILE* scoped_file_pointer::get() const
{
	return m_file;
}

} // end test_helpers
