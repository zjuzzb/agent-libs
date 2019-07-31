/**
 * @file
 *
 * Implementaiton of scoped_temp_file -- a helper class that will create a
 * temporary file on construction and remove it on destruction.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_temp_file.h"
#include "scoped_file_descriptor.h"

#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <Poco/UUID.h>
#include <Poco/UUIDGenerator.h>

using namespace test_helpers;

scoped_temp_file::scoped_temp_file(const std::string &initial_content, const std::string &extension) :

	m_filename("/tmp/" +
		   Poco::UUIDGenerator::defaultGenerator().create().toString()),
	m_created_successfully(false)
{
	if (!extension.empty())
	{
		m_filename += "." + extension;
	}

	const scoped_file_descriptor fd(creat(m_filename.c_str(), 0600));

	m_created_successfully = fd.is_valid();

	if (!m_created_successfully)
	{
		return;
	}

	if (!initial_content.empty())
	{
		  std::ofstream myfile;
		  myfile.open(m_filename);
		  myfile << initial_content;
		  myfile.close();
	}
}

scoped_temp_file::~scoped_temp_file()
{
	unlink(m_filename.c_str());
}

const std::string& scoped_temp_file::get_filename() const
{
	return m_filename;
}

bool scoped_temp_file::created_successfully() const
{
	return m_created_successfully;
}
