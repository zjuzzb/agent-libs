#include <string>
#include <set>
#include <vector>

#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "../../driver/ppm_events_public.h"

#include <gtest.h>

using namespace std;

class evttype_filter_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
		f1 = new sinsp_filter(NULL);
		f2 = new sinsp_filter(NULL);

		f1_evttypes.insert(PPME_SYSCALL_OPEN_E);
		f2_evttypes.insert(PPME_SYSCALL_OPEN_E);

		f1_evttypes.insert(PPME_SYSCALL_CLOSE_E);
		f2_evttypes.insert(PPME_SYSCALL_READ_E);

		f1_syscalls.insert(PPM_SC_EXIT);
		f2_syscalls.insert(PPM_SC_EXIT);

		f1_syscalls.insert(PPM_SC_READ);
		f2_syscalls.insert(PPM_SC_WRITE);

		f1_tags.insert("cis");
		f2_tags.insert("cis");

		f1_tags.insert("container");
		f2_tags.insert("memory");

		string sf1 = "f1";
		string sf2 = "f2";
		f.add(sf1, f1_evttypes, f1_syscalls, f1_tags, f1);
		f.add(sf2, f2_evttypes, f2_syscalls, f2_tags, f2);
	}

	virtual void TearDown()
	{
		// f1/f2 will be deleted when f is deleted
	}

	void check_ruleset(uint32_t ruleset,
			   std::list<uint32_t> in_evttypes,
			   std::list<uint32_t> out_evttypes,
			   std::list<uint32_t> in_syscalls,
			   std::list<uint32_t> out_syscalls)
	{
		vector<bool> evttypes;
		vector<bool> syscalls;

		f.evttypes_for_ruleset(evttypes, ruleset);

		for(auto &evttype : in_evttypes)
		{
			ASSERT_TRUE(evttypes[evttype]) << "Evttype " << evttype << " not found in evttypes for ruleset " << ruleset;
		}

		for(auto &evttype : out_evttypes)
		{
			ASSERT_FALSE(evttypes[evttype]) << "Evttype " << evttype << " unexpectedly found in evttypes for ruleset " << ruleset;
		}

		f.syscalls_for_ruleset(syscalls, ruleset);

		for(auto &syscall : in_syscalls)
		{
			ASSERT_TRUE(syscalls[syscall]) << "Syscall " << syscall << " not found in syscalls for ruleset " << ruleset;
		}

		for(auto &syscall : out_syscalls)
		{
			ASSERT_FALSE(syscalls[syscall]) << "Syscall " << syscall << " unexpectedly found in syscalls for ruleset " << ruleset;
		}
	}


	// The filters don't need to be runnable for this test.
	sinsp_evttype_filter f;

	sinsp_filter *f1;
	set<uint32_t> f1_evttypes;
	set<uint32_t> f1_syscalls;
	set<string> f1_tags;

	sinsp_filter *f2;
	set<uint32_t> f2_evttypes;
	set<uint32_t> f2_syscalls;
	set<string> f2_tags;

};

TEST_F(evttype_filter_test, regex)
{
	f.enable(string("f.*"), true, 1);
	f.enable(string("f1"), true, 2);
	f.enable(string("f2"), true, 3);

	check_ruleset(1,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ, PPM_SC_WRITE},
		      {PPM_SC_CREAT});

	check_ruleset(2,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E},
		      {PPME_SYSCALL_READ_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ},
		      {PPM_SC_WRITE, PPM_SC_CREAT});

	check_ruleset(3,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_WRITE},
		      {PPM_SC_READ, PPM_SC_CREAT});
}

TEST_F(evttype_filter_test, tags)
{
	set<string> tags1 = {"cis"};
	set<string> tags2 = {"container"};
	set<string> tags3 = {"memory"};
	f.enable_tags(tags1, true, 1);
	f.enable_tags(tags2, true, 2);
	f.enable_tags(tags3, true, 3);

	check_ruleset(1,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ, PPM_SC_WRITE},
		      {PPM_SC_CREAT});

	check_ruleset(2,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E},
		      {PPME_SYSCALL_READ_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ},
		      {PPM_SC_WRITE, PPM_SC_CREAT});

	check_ruleset(3,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_WRITE},
		      {PPM_SC_READ, PPM_SC_CREAT});
}

TEST_F(evttype_filter_test, regex_remove)
{
	f.enable(string("f.*"), true, 1);

	f.enable(string("f.*"), true, 2);
	f.enable(string("f2"), false, 2);

	// Remove a second time just to check for crashes, etc.
	f.enable(string("f2"), false, 2);

	f.enable(string("f.*"), true, 3);
	f.enable(string("f1"), false, 3);

	// Remove a second time just to check for crashes, etc.
	f.enable(string("f1"), false, 3);

	check_ruleset(1,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ, PPM_SC_WRITE},
		      {PPM_SC_CREAT});

	check_ruleset(2,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E},
		      {PPME_SYSCALL_READ_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ},
		      {PPM_SC_WRITE, PPM_SC_CREAT});

	check_ruleset(3,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_WRITE},
		      {PPM_SC_READ, PPM_SC_CREAT});
}

TEST_F(evttype_filter_test, tag_remove)
{

	set<string> tags1 = {"cis"};
	set<string> tags2 = {"container"};
	set<string> tags3 = {"memory"};
	f.enable_tags(tags1, true, 1);

	f.enable_tags(tags1, true, 2);
	f.enable_tags(tags3, false, 2);

	f.enable_tags(tags1, true, 3);
	f.enable_tags(tags2, false, 3);

	check_ruleset(1,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ, PPM_SC_WRITE},
		      {PPM_SC_CREAT});

	check_ruleset(2,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_CLOSE_E},
		      {PPME_SYSCALL_READ_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_READ},
		      {PPM_SC_WRITE, PPM_SC_CREAT});

	check_ruleset(3,
		      {PPME_SYSCALL_OPEN_E, PPME_SYSCALL_READ_E},
		      {PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_WRITE_E},
		      {PPM_SC_EXIT, PPM_SC_WRITE},
		      {PPM_SC_READ, PPM_SC_CREAT});
}
