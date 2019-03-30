#include <gtest.h>
#include "sinsp_mock.h"

using namespace test_helpers;

TEST(event_builder_test, defaults)
{
	auto event_wrapper = event_builder().generate();
	auto evt = event_wrapper->get();

	// This is just a sanity check so give it an entire 10 seconds of wiggle room.
	const uint64_t ten_seconds_ns = 10000000000;
	const uint64_t now = sinsp_utils::get_current_time_ns();
	ASSERT_GT(evt->get_ts(), now - ten_seconds_ns);
	ASSERT_LT(evt->get_ts(), now + ten_seconds_ns);
	ASSERT_EQ(0x2222, evt->get_cpuid());
	ASSERT_EQ(PPME_SYSCALL_OPEN_E, evt->get_type());
}

TEST(event_builder_test, fields)
{
	const ppm_event_type TYPE = PPME_SYSCALL_CHDIR_E;
	const uint64_t TS = 0x1234432112344321;
	const uint16_t CPUID = 0x4444;

	auto event_wrapper = event_builder().type(PPME_SYSCALL_CHDIR_E)
					    .ts(TS)
					    .cpuid(CPUID)
					    .generate();
	auto evt = event_wrapper->get();

	ASSERT_EQ(TYPE, evt->get_type());
	ASSERT_EQ(TS, evt->get_ts());
	ASSERT_EQ(CPUID, evt->get_cpuid());
}

class my_event_committer
{
public:
	event_builder build_event()
	{
		// Create an event builder that will commit into this class
		return event_builder(std::bind(&my_event_committer::commit_event,
					       this,
					       std::placeholders::_1,
					       std::placeholders::_2));
	}

	int m_commit_counter = 0;
	sinsp_evt_wrapper::ptr m_last_event;
	unsigned int m_last_count = 0;


	void commit_event(const sinsp_evt_wrapper::ptr& event, unsigned int count)
	{
		m_commit_counter++;
		m_last_event = event;
		m_last_count = count;
	}
};


TEST(event_builder_test, commit)
{
	my_event_committer foo;

	foo.build_event().type(PPME_SYSCALL_SPLICE_E).count(8).commit();

	ASSERT_EQ(1, foo.m_commit_counter);
	ASSERT_EQ(PPME_SYSCALL_SPLICE_E, foo.m_last_event->get()->get_type());
	ASSERT_EQ(8, foo.m_last_count);

	foo.build_event().commit();
	foo.build_event().commit();
	foo.build_event().commit();

	ASSERT_EQ(4, foo.m_commit_counter);
	ASSERT_EQ(PPME_SYSCALL_OPEN_E, foo.m_last_event->get()->get_type());
	ASSERT_EQ(1, foo.m_last_count);
}
