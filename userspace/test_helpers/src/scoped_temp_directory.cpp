/**
 * @file
 *
 * Implementaiton of scoped_temp_directory -- a helper class that will create a
 * temporary directory on construction and remove it on destruction.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_temp_directory.h"

#include <exception>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <Poco/UUID.h>
#include <Poco/UUIDGenerator.h>

using namespace test_helpers;

namespace
{

/**
 * Open the given directory on construction and close it on destruction.
 */
class scoped_directory_handle
{
public:
	/**
	 * Opens the given directory.
	 *
	 * @param[in] dirname The name of the directory to open
	 *
	 * @throws std::runtime_error if the directory cannot be opened.
	 */
        scoped_directory_handle(const std::string& dirname):
                m_directory(opendir(dirname.c_str()))
        {
		if(m_directory == nullptr)
		{
			throw std::runtime_error("scoped_directory_handle: Failed "
			                         "to opedir() on " +
			                         dirname);
		}
	}

	~scoped_directory_handle()
	{
		if(m_directory != nullptr)
		{
			closedir(m_directory);
		}
	}

	/**
	 * Iterates over the content of this directory.
	 */
	const struct dirent* next()
	{
		return ::readdir(m_directory);
	}

private:
        DIR* const m_directory;
};

/**
 * Remove all files and directories rooted at the given path.
 *
 * @throws std::runtime_error if the given path doesn't exist or if it cannot
 *         be removed.
 */
void rm_rf(const std::string& path)
{
	struct stat statbuf = {};

	if(stat(path.c_str(), &statbuf) != 0)
	{
		throw std::runtime_error("Failed to stat() " + path);
	}

	if(S_ISDIR(statbuf.st_mode))
	{
		scoped_directory_handle dir(path);

                for(const struct dirent* entry = dir.next();
                    entry != nullptr;
                    entry = dir.next())
                {
                        const std::string name = entry->d_name;

                        if((name == ".") || (name == ".."))
                        {
                                continue;
                        }

			rm_rf(path + "/" + name);
                }
	}

	if(remove(path.c_str()) != 0)
	{
		throw std::runtime_error("Failed to remove() " + path);
	}
}

} // end namespace

scoped_temp_directory::scoped_temp_directory(const std::string& base):
	m_directory(base + "/tempdir_" +
		   Poco::UUIDGenerator::defaultGenerator().create().toString()),
	m_created_successfully(mkdir(m_directory.c_str(), 0700) == 0)
{
	if (!m_created_successfully)
	{
		throw std::runtime_error("scoped_temp_directory: Failed to "
		                         "create temp directory " +
		                         m_directory);
	}
}

scoped_temp_directory::~scoped_temp_directory()
{
	if(m_created_successfully)
	{
		rm_rf(m_directory);
	}
}

const std::string& scoped_temp_directory::get_directory() const
{
	return m_directory;
}
