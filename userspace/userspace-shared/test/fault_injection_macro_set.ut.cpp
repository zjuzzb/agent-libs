/**
 * @file
 *
 * Unit test for fault_injection when FAULT_INJECTION_ENABLED is set
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)
#include "fault_injection.h"
#include "fault_handler.h"
#include <gtest.h>

using userspace_shared::fault_handler;

namespace
{

const std::string FILENAME = "foo.cpp";
const uint16_t LINE = 18;
const std::string NAME = "this.that";
const std::string DESCRIPTION = "some description";

} // end namespace

// Note that we're explicitly not using DEFINE_FAULT_INJECTOR because
// it makes the objects static.

TEST(fault_injection_enabled_test, FAULT_FIRED)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_enabled(true);

	ASSERT_TRUE(FAULT_FIRED(fh));
}

TEST(fault_injection_enabled_test, FAULT_FIRED_INVOKE_void)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);
	bool fired = false;

	fh.set_enabled(true);

	ASSERT_TRUE(FAULT_FIRED_INVOKE(fh, [&fired]() { fired = true; }));
	ASSERT_TRUE(fired);
}

TEST(fault_injection_enabled_test, FAULT_FIRED_INVOKE_string)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);
	const std::string fault_string = "this is a fault string";

	fh.set_fault_string(fault_string);
	fh.set_enabled(true);

	std::string fault_value;
	ASSERT_TRUE(FAULT_FIRED_INVOKE(fh, [&fault_value](const std::string& v) { fault_value = v; }));
	ASSERT_EQ(fault_string, fault_value);
}

TEST(fault_injection_enabled_test, FAULT_FIRED_INVOKE_uint64)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);
	const uint64_t fault_uint64 = 54321;

	fh.set_fault_uint64(fault_uint64);
	fh.set_enabled(true);

	uint64_t fault_value = 0;
	ASSERT_TRUE(FAULT_FIRED_INVOKE(fh, [&fault_value](uint64_t v) { fault_value = v; }));
	ASSERT_EQ(fault_uint64, fault_value);
}

TEST(fault_injection_enabled_test, FAULT_FIRED_INVOKE_string_uint64)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);
	const std::string fault_string = "this is a fault string";
	const uint64_t fault_uint64 = 54321;

	fh.set_fault_string(fault_string);
	fh.set_fault_uint64(fault_uint64);
	fh.set_enabled(true);

	std::string fault_value_string;
	uint64_t fault_value_uint64 = 0;

	auto fn = [&fault_value_string, &fault_value_uint64](const std::string& s, uint64_t v)
	{
		fault_value_string = s;
		fault_value_uint64 = v;
	};

	ASSERT_TRUE(FAULT_FIRED_INVOKE(fh, fn));
	ASSERT_EQ(fault_string, fault_value_string);
	ASSERT_EQ(fault_uint64, fault_value_uint64);
}

TEST(fault_injection_enabled_test, FAULT_RETURN)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	auto fn = [&fh]()
	{
		FAULT_RETURN(fh, true);
		return false;
	};

	fh.set_enabled(true);

	ASSERT_TRUE(fn());
}

#endif /* defined(FAULT_INJECTION_ENABLED) */
