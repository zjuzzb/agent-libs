/**
 * @file
 *
 * Unit test for fault_injection when FAULT_INJECTION_ENABLED is NOT set
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
//
// Force the feature disabled within this file (independent of whether or not
// it's generally enabled).  This will cause the inclusion of fault_injection.h
// to define the macros in disabled mode.
//
#undef FAULT_INJECTION_ENABLED

#include "fault_injection.h"
#include <gtest.h>

TEST(fault_injection_disabled_test, FAULT_FIRED)
{
	DEFINE_FAULT_INJECTOR(fh, XXX, XXX);
	ASSERT_FALSE(FAULT_FIRED(fh));
}

TEST(fault_injection_disabled_test, FAULT_FIRED_INVOKE_void)
{
	DEFINE_FAULT_INJECTOR(fh, XXX, XXX);
	bool fired = false;

	ASSERT_FALSE(FAULT_FIRED_INVOKE(fh, [&fired]() { fired = true; }));
	ASSERT_FALSE(fired);
}

TEST(fault_injection_disabled_test, FAULT_FIRED_INVOKE_string)
{
	DEFINE_FAULT_INJECTOR(fh, XXX, XXX);

	std::string fault_value = "hello";
	ASSERT_FALSE(FAULT_FIRED_INVOKE(fh, [&fault_value](const std::string& v) { fault_value = v; }));
	ASSERT_EQ("hello", fault_value);
}

TEST(fault_injection_disabled_test, FAULT_FIRED_INVOKE_uint64)
{
	DEFINE_FAULT_INJECTOR(fh, XXX, XXX);

	uint64_t fault_value = 13579;
	ASSERT_FALSE(FAULT_FIRED_INVOKE(fh, [&fault_value](uint64_t v) { fault_value = v; }));
	ASSERT_EQ(13579, fault_value);
}

TEST(fault_injection_disabled_test, FAULT_FIRED_INVOKE_string_uint64)
{
	DEFINE_FAULT_INJECTOR(fh, XXX, XXX);

	std::string fault_value_string = "four score and seven years ago";
	uint64_t fault_value_uint64 = 1863;


	ASSERT_FALSE(FAULT_FIRED_INVOKE(fh, 
		([&fault_value_string, &fault_value_uint64](const std::string& s, uint64_t v)
		{
			fault_value_string = s;
			fault_value_uint64 = v;
		})));
	ASSERT_EQ("four score and seven years ago", fault_value_string);
	ASSERT_EQ(1863, fault_value_uint64);
}

TEST(fault_injection_disabled_test, FAULT_RETURN)
{
	auto fn = []()
	{
		DEFINE_FAULT_INJECTOR(fh, XXX, XXX);

		FAULT_RETURN(fh, true);
		return false;
	};

	ASSERT_FALSE(fn());
}
