/**
 * @file
 *
 * Interface to scoped_temp_directory -- a helper class that will create a
 * temporary directory on construction and remove it (and its contents) on
 * destruction.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace test_helpers
{

/**
 * Create a temp directory that lasts for the lifetime of the object.  The
 * directory will be in the form of "/tmp/<uuid>/".
 */
class scoped_temp_directory
{
public:
	/**
	 * Creates a new scoped temporary directory.
	 *
	 * @param[in] base The base directory for the temporary directory.
	 *                 This should not contain a trailing directory
	 *                 delimiter.
	 *
	 * @throws std::runtime_error if the directory could not be created.
	 */
	scoped_temp_directory(const std::string& base = "/tmp");
	~scoped_temp_directory();

	/**
	 * Returns the name of the temporary directory.
	 */
	const std::string& get_directory() const;

private:
	std::string m_directory;
	bool m_created_successfully;
};

} // end namespace test
