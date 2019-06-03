/**
 * @file
 *
 * Unit tests for scoped_sinsp_logger_capture.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "scoped_sinsp_logger_capture.h"
#include <logger.h>
#include <gtest.h>

TEST(scoped_sinsp_logger_capture_test, basic)
{
	test_helpers::scoped_sinsp_logger_capture capture;
	g_logger.log("can't stop", sinsp_logger::SEV_ERROR);
	g_logger.log("won't stop", sinsp_logger::SEV_ERROR);
	g_logger.log("get guap", sinsp_logger::SEV_ERROR);
	g_logger.log("ten white toes in my Tori flip flops", sinsp_logger::SEV_FATAL);

	ASSERT_TRUE(capture.get().find("SEV_ERROR") != std::string::npos);

	ASSERT_TRUE(capture.find("guap"));
	ASSERT_FALSE(capture.find("guac"));
	ASSERT_TRUE(capture.find("stop"));
}
