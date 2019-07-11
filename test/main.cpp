#include "avoid_block_channel.h"
#include "common_logger.h"
#include "sys_call_test.h"
#include <cstdlib>
#include <gtest.h>
#include <SimpleOpt.h>
#include <Poco/AutoPtr.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/FormattingChannel.h>
#include <Poco/File.h>
#include <Poco/FileChannel.h>
#include <Poco/Logger.h>
#include <Poco/Path.h>
#include <Poco/PatternFormatter.h>

using namespace Poco;

using namespace std;

namespace {

class dragent_environment : public ::testing::Environment {

public:
	dragent_environment(bool log_to_console) :
	   m_log_to_console(log_to_console)
	{}

private:

	void setup_common_logger()
	{
		std::string logDir  = "/opt/draios/logs";
		File d(logDir);
		d.createDirectories();
		Path p;
		p.parseDirectory(logDir);
		p.setFileName("draios_test.log");
		string logsdir = p.toString();

		AutoPtr<FileChannel> file_channel(new FileChannel(logsdir));

		file_channel->setProperty("purgeCount", std::to_string(10));
		file_channel->setProperty("rotation", "10M");
		file_channel->setProperty("archive", "timestamp");

		AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));
		AutoPtr<Channel> avoid_block(new avoid_block_channel(file_channel, "machine_test"));
		AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, avoid_block));

		Logger *loggerc = 0;
		if(m_log_to_console)
		{
			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
			loggerc = &Logger::create("DraiosLogC", formatting_channel_console, Message::Priority::PRIO_DEBUG);
		}

		Logger& loggerf = Logger::create("DraiosLogF", formatting_channel_file, Message::Priority::PRIO_DEBUG);

		g_log = unique_ptr<common_logger>(new common_logger(&loggerf, loggerc));
	}

	void SetUp() override
	{
		setup_common_logger();
	}

	void TearDown() override
	{
	}

	bool m_log_to_console;

};

}


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
			string dump_filename = string("./captures/") + test_info.test_case_name() + "_	" + test_info.name() + ".scap";
			remove(dump_filename.c_str());
		}
	}
private:
	bool m_keep_capture_files;
};

// define the ID values to indentify the option
enum { OPT_KEEP_CAPTURE_FILES, OPT_LOG_TO_CONSOLE };

// declare a table of CSimpleOpt::SOption structures. See the SimpleOpt.h header
// for details of each entry in this structure. In summary they are:
//  1. ID for this option. This will be returned from OptionId() during processing.
//     It may be anything >= 0 and may contain duplicates.
//  2. Option as it should be written on the command line
//  3. Type of the option. See the header file for details of all possible types.
//     The SO_REQ_SEP type means an argument is required and must be supplied
//     separately, e.g. "-f FILE"
//  4. The last entry must be SO_END_OF_OPTIONS.
//
CSimpleOpt::SOption g_rgOptions[] =
{
	{ OPT_KEEP_CAPTURE_FILES, "--keep_capture_files", SO_NONE    }, // "--help"
	{ OPT_LOG_TO_CONSOLE, "-v",  SO_NONE },
	{ OPT_LOG_TO_CONSOLE, "--verbose",  SO_NONE },
	SO_END_OF_OPTIONS                       // END
};


int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	bool keep_capture_files = false;
	bool log_to_console = false;
	CSimpleOpt args(argc, argv, g_rgOptions);

	//
	// process arguments ignoring all but --keep_capture_files
	//
	while(args.Next())
	{
		if(args.LastError() == SO_SUCCESS)
		{
			if(args.OptionId() == OPT_KEEP_CAPTURE_FILES)
			{
				keep_capture_files = true;
			}
			else if(args.OptionId() == OPT_LOG_TO_CONSOLE)
			{
				log_to_console = true;
			}
		}
	}

	::testing::TestEventListeners &listeners = ::testing::UnitTest::GetInstance()->listeners();
	listeners.Append(new EventListener(keep_capture_files));

	::testing::AddGlobalTestEnvironment(new dragent_environment(log_to_console));

	return RUN_ALL_TESTS();
}

