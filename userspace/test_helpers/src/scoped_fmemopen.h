/**
 * @file
 *
 * Interface to scoped_fmemopen.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "scoped_file_pointer.h"
#include <cstdio>
#include <string>
#include <vector>

namespace test_helpers
{

/**
 * RAII wrapper over fmemopen().  This API expects the content to be
 * read/written to be text; it does not support binary data.
 */
class scoped_fmemopen
{
public:
	/**
	 * Create a new memory buffer of the given buffer size and a new
	 * open FILE* associated with that member buffer.  Initialize the
	 * member buffer to the given initial_state.
	 *
	 * @param[in] buffer_size   The size of underlying memory buffer to/from
	 *                          which file I/O operations will interact.
	 * @param[in] mode          The mode with which this scoped_fmemopen
	 *                          will open the buffer (see fmemopen(3)).
	 * @param[in] initial_state The initial content of the memory buffer
	 *                          (empty by default).
	 */
	scoped_fmemopen(size_t buffer_size,
			const std::string& mode,
	                const std::string& initial_state = "");

	/**
	 * Returns the file pointer associated with this scoped_fmemopen.
	 */
	FILE* get_file();

	/**
	 * Returns a string representation of the content of the memory
	 * buffer.
	 */
	std::string get_buffer_content() const;

	/**
	 * Updates the content of the memory buffer to the given value.  If
	 * the given content is too large to fit into the memory buffer
	 * associated with this scoped_fmemopen, then this method will
	 * copy only what fits, and will truncate anything else.
	 *
	 * @param[in] content The new content for the memory buffer.
	 */
	void set_buffer_content(const std::string& content);

private:
	/** The memory buffer */
	std::vector<char> m_buffer;

	/** Manages the FILE pointer */
	scoped_file_pointer m_file;
};

} // namespace test_helpers
