#include <gtest.h>
#include "sinsp_mock.h"

using namespace test_helpers;

// Ensure that the mock can be used to generate a thread
TEST(sinsp_mock_test, build_thread)
{
	const int64_t tid = 0x100;
	const std::string exe = "my_exe";

	sinsp_mock mock;
	(void)mock.build_thread().tid(tid).exe(exe).commit();

	mock.open();

	// Pull the thread out of sinsp
	auto tinfo = mock.get_thread(tid);
	ASSERT_EQ(exe, tinfo->m_exe);
}

// Ensure that the mock can be used to generate a container
TEST(sinsp_mock_test, build_container)
{
	const std::string container_id = "123456";
	const std::string container_name = "my_container";

	sinsp_mock mock;
	(void)mock.build_container().id(container_id).name(container_name).commit();

	mock.open();

	// Pull the container out of the container manager
	auto cinfo = mock.m_container_manager.get_container(container_id);
	ASSERT_EQ(container_name, cinfo->m_name);
}

// Ensure that the mock can be used to generate a container with a thread
TEST(sinsp_mock_test, build_container_with_thread)
{
	const uint64_t thread_pid = 0x123456;
	const std::string container_id = "123456";
	const std::string container_name = "my_container";

	sinsp_mock mock;
	{
		auto& tinfo = mock.build_thread().pid(thread_pid).commit();
		(void)mock.build_container(tinfo).id(container_id).name(container_name).commit();
	}

	mock.open();

	// Pull the container out of the container manager
	auto cinfo = mock.m_container_manager.get_container(container_id);
	ASSERT_EQ(container_name, cinfo->m_name);
	sinsp_threadinfo* tinfo = mock.get_thread(thread_pid);
	ASSERT_EQ(container_id, tinfo->m_container_id);
}

// Ensure that the mock can be used to generate an event
TEST(sinsp_mock_test, single_event)
{
	sinsp_mock mock;
	auto &tinfo = mock.build_thread().commit();
	mock.build_event(tinfo).commit();

	mock.open();

	sinsp_evt *event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(SCAP_EOF, mock.next(&event));
}

// Ensure that the mock can be used to generate a number of events.
TEST(sinsp_mock_test, multiple_events)
{
	const uint16_t CPUID = 0xABC;

	sinsp_mock mock;
	auto &tinfo = mock.build_thread().commit();
	mock.build_event(tinfo).count(3).cpuid(CPUID).commit();

	mock.open();

	sinsp_evt *event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(CPUID, event->get_cpuid());
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(CPUID, event->get_cpuid());
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(CPUID, event->get_cpuid());
	ASSERT_EQ(SCAP_EOF, mock.next(&event));
}

// Ensure that the thread_builder and event_builder can be used together
TEST(sinsp_mock_test, thread_and_event)
{
	const int64_t tid = 0x1234;
	const std::string comm = "wireshark";

	sinsp_mock mock;
	auto &tinfo = mock.build_thread().tid(tid).comm(comm).commit();
	mock.build_event(tinfo).commit();

	mock.open();

	sinsp_evt *event;
	mock.next(&event);

	// Search for the comm via the event to make sure they are connected
	// together.
	sinsp_threadinfo *event_tinfo = event->get_thread_info(false /*don't query os*/);
	ASSERT_EQ(event_tinfo->m_comm, comm);
}
