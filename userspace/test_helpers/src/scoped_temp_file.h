/**
 * @file
 *
 * Interface to scoped_temp_file -- a helper class that will create a temporary
 * file on construction and remove it on destruction.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace test_helpers
{

/**
 * Create a temp file that lasts for the lifetime of the object.  The filename
 * will be in the form of "/tmp/<uuid>".
 */
class scoped_temp_file
{
public:
	scoped_temp_file(const std::string& initial_content = "",
			 const std::string& extension = "");
	~scoped_temp_file();

	const std::string& get_filename() const;
	bool created_successfully() const;

private:
	std::string m_filename;
	bool m_created_successfully;
};

} // end namespace test
