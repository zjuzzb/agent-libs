#pragma once

#include "common_logger.h"
#include "Poco/Logger.h"
#include "Poco/Formatter.h"
#include "Poco/FormattingChannel.h"
#include "Poco/PatternFormatter.h"
#include "Poco/ConsoleChannel.h"


/*!
 * Enable dragent logging in UTs.
 * Sometime it is useful to see the usual familiar dragent logging
 * in UT as well. This class is ment to do this.
 * Basic usage is to create a fixture for your UTs that inherits from test_logger
 * as well as testing::Test
 * then just call setup_logger somewhere in your UT
 */
class test_logger
{
public:
	test_logger();
	~test_logger();

	/*!
	 * call this member inside your UT to enable logging
	 */
	void setup_logger();
};
