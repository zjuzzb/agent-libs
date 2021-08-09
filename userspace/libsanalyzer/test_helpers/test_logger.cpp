#include "test_logger.h"

#include "Poco/AutoPtr.h"
#include "Poco/NullChannel.h"
#include <memory>

extern std::unique_ptr<common_logger> g_log;

test_logger::test_logger()
{
}

test_logger::~test_logger()
{
}

void test_logger::setup_logger()
{
	Poco::AutoPtr<Poco::Formatter> formatter(new Poco::PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P.%I, %p, %t"));

	Poco::AutoPtr<Poco::Channel> console_channel(new Poco::ConsoleChannel());
	Poco::AutoPtr<Poco::Channel> formatting_channel_console(
		new Poco::FormattingChannel(formatter, console_channel));

	Poco::Logger& loggerc = Poco::Logger::create("DraiosLogC",
						     formatting_channel_console,
						     Poco::Message::Priority::PRIO_DEBUG);

	// Not interested in file channel in tests
	Poco::AutoPtr<Poco::Channel> null_channel(new Poco::NullChannel);
	Poco::Logger& null_file_logger = Poco::Logger::create("DraiosLogF",
			     null_channel,
			     Poco::Message::Priority::PRIO_TRACE);

	g_log = std::unique_ptr<common_logger>(new common_logger(&null_file_logger, &loggerc));

}
