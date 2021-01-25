#include <gtest.h>
#include <string>
#include "common_logger.h"
#include "avoid_block_channel.h"
#include "globally_readable_file_channel.h"
#include <Poco/AutoPtr.h>
#include <Poco/Channel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/File.h>
#include <Poco/Formatter.h>
#include <Poco/FormattingChannel.h>
#include <Poco/Logger.h>
#include <Poco/Message.h>
#include <Poco/Path.h>
#include <Poco/PatternFormatter.h>

using namespace Poco;
using namespace dragent;

namespace
{
class agentone_environment : public ::testing::Environment {

public:
	agentone_environment(bool log_to_console) :
	   m_log_to_console(log_to_console)
	{}

private:

	void setup_common_logger()
	{
		std::string logDir  = "/tmp";
		File d(logDir);
		d.createDirectories();
		Path p;
		p.parseDirectory(logDir);
		p.setFileName("draios_test.log");
		std::string logsdir = p.toString();

		AutoPtr<globally_readable_file_channel> file_channel(new globally_readable_file_channel(logsdir, false));

		file_channel->setProperty("purgeCount", std::to_string(10));
		file_channel->setProperty("rotation", "10M");
		file_channel->setProperty("archive", "timestamp");

		AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));
		AutoPtr<Channel> avoid_block(new avoid_block_channel(file_channel, "machine_test"));
		AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, avoid_block));

		Logger *loggerc = nullptr;
		if(m_log_to_console)
		{
			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
			loggerc = &Logger::create("DraiosLogC", formatting_channel_console, Message::Priority::PRIO_DEBUG);
		}

		Logger& loggerf = Logger::create("DraiosLogF", formatting_channel_file, Message::Priority::PRIO_DEBUG);
		std::vector<std::string> dummy_config;
		g_log = std::unique_ptr<common_logger>(new common_logger(&loggerf,
									 Message::Priority::PRIO_DEBUG,
									 dummy_config,
									 loggerc));
	}

	void SetUp() override
	{
		setup_common_logger();
	}

	bool m_log_to_console;

};

class EventListener : public ::testing::EmptyTestEventListener
{
public:
	EventListener(bool keep_capture_files)
	{
		m_keep_capture_files = keep_capture_files;
	}

	// Called before a test starts.
	virtual void OnTestStart(const ::testing::TestInfo &test_info)
	{
	}

	// Called after a failed assertion or a SUCCEED() invocation.
	virtual void OnTestPartResult(
	    const ::testing::TestPartResult &test_part_result)
	{
	}

	// Called after a test ends.
	virtual void OnTestEnd(const ::testing::TestInfo &test_info)
	{
		if(!m_keep_capture_files && !test_info.result()->Failed())
		{
			std::string dump_filename = std::string("./captures/") + test_info.test_case_name() + "_	" + test_info.name() + ".scap";
			remove(dump_filename.c_str());
		}
	}
private:
	bool m_keep_capture_files;
};
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
	bool log = false;

	for (int i = 1; i < argc; ++i)
	{
		std::string opt = argv[i];
		if (opt == "-v" || opt == "--verbose")
		{
			log = true;
		}
	}

	::testing::AddGlobalTestEnvironment(new agentone_environment(log));
    return RUN_ALL_TESTS();
}

