#include <gtest.h>
#include "dragent/logger.h"

DRAGENT_LOGGER("test:dragent");

class logger_test
{
public:
	static std::string build_this(int line, const std::string &msg)
	{
		return s_file_logger.build(line, msg);
	}
};

TEST(logger_test, basic)
{
	// Test the string builder. Use 99 as the line number in both this
	// call and the validation string.
	std::string message = logger_test::build_this(99, "something happened");
	ASSERT_EQ(message, std::string("test:dragent:logger.ut:99: something happened"));
}

TEST(logger_test, long_string)
{
	// Test the string builder. Use 99 as the line number in both this
	// call and the validation string.
	std::string long_message =
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. "
		"This is a really long message. I mean not THAT long, but I definitely don't think anyone would call this a short message. ";

	std::string message = logger_test::build_this(99, long_message);
	ASSERT_EQ(message, std::string("test:dragent:logger.ut:99: " + long_message));
}
