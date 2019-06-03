/**
 * @file
 *
 * Helper class to capture and analyze what is sent to
 * sinsp_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>

namespace test_helpers
{

/**
 * Capture all data that was sent to the sinsp logger when this
 * class is in scope.
 *
 * Example:
 * scoped_sinsp_logger_capture capture;
 * ... do things ...
 * ASSERT_TRUE(capture.find("message I care about"));
 */
class scoped_sinsp_logger_capture
{
public:
	scoped_sinsp_logger_capture();
	~scoped_sinsp_logger_capture();

	/**
	 * Returns whether the given string exists in the captured data
	 */
	bool find(const char *value);

	/**
	 * Return everything captured
	 */
	const std::string &get();
};

} // namespace test_helpers


