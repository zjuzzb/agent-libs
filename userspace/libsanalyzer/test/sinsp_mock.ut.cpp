#include <gtest.h>
#include "sinsp_mock.h"

using namespace test_helpers;

TEST(sinsp_mock_test, single_event)
{
	sinsp_mock mock;

	mock.build_event().commit();

	sinsp_evt *event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(SCAP_EOF, mock.next(&event));
}

TEST(sinsp_mock_test, multiple_events)
{
	const uint16_t CPUID = 0xABC;

	sinsp_mock mock;
	mock.build_event().count(3).cpuid(CPUID).commit();

	sinsp_evt *event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(CPUID, event->get_cpuid());
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(CPUID, event->get_cpuid());
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));
	ASSERT_EQ(CPUID, event->get_cpuid());
	ASSERT_EQ(SCAP_EOF, mock.next(&event));
}
