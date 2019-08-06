/**
 * @file
 *
 * Interface to scoped_file_pointer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdio>
#include <string>

namespace test_helpers
{

/**
 * RAII wrapper over FILE*
 */
class scoped_file_pointer
{
public:
	/**
	 * Initialize this scoped_file_pointer by using fopen() to open the
	 * given filename in the given mode.
	 *
	 * @param[in] filename The name of the file to open
	 * @param[in] mode     The mode with which to open the file.
	 *
	 * @throws std::runtime_error if fopen fails.
	 */
	scoped_file_pointer(const std::string& filename,
	                    const std::string& mode);
	/**
	 * Initialize this scoped_file_pointer with the given file.
	 *
	 * @param[in] file The FILE pointer to protect.
	 */
	scoped_file_pointer(FILE* file);

	/**
	 * Closes the associated file.
	 */
	~scoped_file_pointer();

	scoped_file_pointer(const scoped_file_pointer&) = delete;
	scoped_file_pointer(scoped_file_pointer&&) = delete;
	scoped_file_pointer& operator=(const scoped_file_pointer&) = delete;
	scoped_file_pointer& operator=(scoped_file_pointer&&) = delete;

	/**
	 * Returns the file pointer.
	 */
	FILE* get() const;

private:
	FILE* const m_file;
};

} // end test_helpers
