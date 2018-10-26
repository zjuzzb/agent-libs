#include <gtest.h>
#include "dragent/logger.h"

DRAGENT_LOGGER("test:dragent");

class logger_test
{
public:
	static std::string build_this(int line, const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		std::string message = s_file_logger.build(line, fmt, args);
		va_end(args);
		return message;
	}
};

TEST(logger_test, basic)
{
	// Test the string builder. Use 99 as the line number in both this
	// call and the validation string.
	std::string message = logger_test::build_this(99, "something happened: %04X", 0x999);
	ASSERT_EQ(message, std::string("test:dragent:logger_ut:99: something happened: 0999"));
}
