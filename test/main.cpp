#include <cstdlib>
#include "sys_call_test.h"
#include <gtest.h>
#include <SimpleOpt.h>

using namespace std;


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
enum { OPT_KEEP_CAPTURE_FILES };

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
	SO_END_OF_OPTIONS                       // END
};


int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	bool keep_capture_files = false;
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
		}
	}

	::testing::TestEventListeners &listeners = ::testing::UnitTest::GetInstance()->listeners();
	listeners.Append(new EventListener(keep_capture_files));
	return RUN_ALL_TESTS();
}

