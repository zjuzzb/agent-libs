/**
 * @file
 *
 * Helper class to capture and analyze stdout.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "scoped_temp_file.h"
#include <string>

namespace test_helpers
{

/**
 * Capture all data that was sent to the std::out when this
 * class is in scope.
 *
 * Example:
 * scoped_stdout_capture capture;
 * ... do things ...
 * ASSERT_TRUE(capture.find("message I care about"));
 */
class scoped_stdout_capture
{
public:
	scoped_stdout_capture();
	~scoped_stdout_capture();

	/**
	 * Returns whether the given string exists in the captured data
	 */
	bool find(const char *value);

	/**
	 * Return everything captured
	 */
	std::string get();
private:
	void put_stdout_back();

	bool m_closed;
	int m_stdout_fd;
	scoped_temp_file m_redirected_file;
};

} // namespace test_helpers

