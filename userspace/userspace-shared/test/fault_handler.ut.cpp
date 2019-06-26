/**
 * @file
 *
 * Unit tests for fault_handler.
 *
 * @copyright Copyright (c) 2019 Sysdig, Inc., All Rights Reserved
 */
#if defined(FAULT_INJECTION_ENABLED)

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

/**
 * Ensure that get_filename() returns the expected filename.
 */
TEST(fault_handler_test, get_filename)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(FILENAME, fh.get_filename());
}

/**
 * Ensure that get_line() returns the expected line number.
 */
TEST(fault_handler_test, get_line)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(LINE, fh.get_line());
}

/**
 * Ensure that get_name() returns the expected fault name.
 */
TEST(fault_handler_test, get_name)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(NAME, fh.get_name());
}

/**
 * Ensure that get_description() returns the expected description.
 */
TEST(fault_handler_test, get_description)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(DESCRIPTION, fh.get_description());
}

/**
 * Ensure that the initial fault mode is ALWAYS.
 */
TEST(fault_handler_test, initial_fault_mode)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(fault_handler::fault_mode::ALWAYS, fh.get_fault_mode());
}

/**
 * Ensure that the initial fired count is zero.
 */
TEST(fault_handler_test, initial_fired_count_is_zero)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(0, fh.get_fired_count());
}

/**
 * Ensure that the initial hit count is zero.
 */
TEST(fault_handler_test, initial_hit_count_is_zero)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(0, fh.get_hit_count());
}

/**
 * Ensure that a newly-create fault handler is initially disabled.
 */
TEST(fault_handler_test, initially_disabled)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_FALSE(fh.is_enabled());
}

/**
 * Ensure that a newly-create fault handler's fault probability is 100 percent.
 */
TEST(fault_handler_test, initial_fault_probability)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(100, fh.get_fault_probability());
}

/**
 * Ensure that a newly-create fault handler's n-count is 0.
 */
TEST(fault_handler_test, initial_n_count)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	ASSERT_EQ(0, fh.get_n_count());
}

/**
 * Ensure that set_enabled() enables a fault handler.
 */
TEST(fault_handler_test, set_enabled)
{
	const bool enabled = true;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(enabled);

 	ASSERT_EQ(enabled, fh.is_enabled());
}

/**
 * Ensure that set_fault_string() updates the fault handler's fault string.
 */
TEST(fault_handler_test, set_fault_string)
{
	const std::string fault_string = "my fault string";
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_fault_string(fault_string);

 	ASSERT_EQ(fault_string, fh.get_fault_string());
}

/**
 * Ensure that set_fault_uint64() updates the fault handler's fault uint64.
 */
TEST(fault_handler_test, set_fault_uint64)
{
	const uint64_t fault_value = 42;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_fault_uint64(fault_value);

 	ASSERT_EQ(fault_value, fh.get_fault_uint64());
}

/**
 * Ensure that set_fault_mode() updates the fault handler's fault mode.
 */
TEST(fault_handler_test, set_fault_mode)
{
	const fault_handler::fault_mode mode = fault_handler::fault_mode::PROBABILITY;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_fault_mode(mode);

 	ASSERT_EQ(mode, fh.get_fault_mode());
}

/**
 * Ensure that set_fault_probability() updates the fault handler's fault
 * probability.
 */
TEST(fault_handler_test, set_fault_probability)
{
	const uint8_t probability = 50;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_fault_probability(probability);

 	ASSERT_EQ(probability, fh.get_fault_probability());
}

/**
 * Ensure that set_fault_probability() when given a probability greater than
 * 100 stores 100.
 */
TEST(fault_handler_test, set_fault_probability_greater_than_100)
{
	const uint8_t probability = 100;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_fault_probability(probability + 1);

 	ASSERT_EQ(probability, fh.get_fault_probability());
}

/**
 * Ensure that when a fault should fire, fired() returns true and increments
 * the fired and hit counts.
 */
TEST(fault_handler_test, fired_when_enabled_increments_fired_count)
{
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(true);

 	ASSERT_TRUE(fh.fired());
 	ASSERT_EQ(1, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should not fire, fired() returns false, does not
 * increment the fired count, but does fire the hit count.
 */
TEST(fault_handler_test, fired_when_disables_does_not_increment_fired_count)
{
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(false);

 	ASSERT_FALSE(fh.fired());
 	ASSERT_EQ(0, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should fire, fired(string) returns true, returns
 * the fault_string, and increments the fired and hit counts.
 */
TEST(fault_handler_test, fired_string_when_enabled_increments_fired_count)
{
	const std::string fault_string = "my fault string";
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(true);
 	fh.set_fault_string(fault_string);

	std::string fault_value;

 	ASSERT_TRUE(fh.fired([&fault_value](const std::string& s) { fault_value = s; }));
 	ASSERT_EQ(fault_string, fault_value);
 	ASSERT_EQ(1, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should not fire, fired(string) returns false,
 * does not modify the fault_string, does not increment the fired count,
 * but does increment the hit count.
 */
TEST(fault_handler_test, fired_string_when_disables_does_not_increment_fired_count)
{
	const std::string fault_string = "my fault string";
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(false);
 	fh.set_fault_string(fault_string);

	std::string fault_value;

 	ASSERT_FALSE(fh.fired([&fault_value](const std::string& s) { fault_value = s; }));
 	ASSERT_EQ("", fault_value);
 	ASSERT_EQ(0, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should fire, fired(uint64) returns true, returns
 * the fault_uint64, and increments the fired and hit counts.
 */
TEST(fault_handler_test, fired_uint64_when_enabled_increments_fired_count)
{
	const uint64_t fault_uint64 = 1337;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(true);
 	fh.set_fault_uint64(fault_uint64);

	uint64_t fault_value = 0;

 	ASSERT_TRUE(fh.fired([&fault_value](const uint64_t v) { fault_value = v; }));
 	ASSERT_EQ(fault_uint64, fault_value);
 	ASSERT_EQ(1, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should not fire, fired(uint64) returns false,
 * does not modify the fault_uint64, does not increment the fired count,
 * but does increment the hit count.
 */
TEST(fault_handler_test, fired_uint64_when_disables_does_not_increment_fired_count)
{
	const uint64_t fault_uint64 = 1337;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(false);
 	fh.set_fault_uint64(fault_uint64);

	uint64_t fault_value = 0;

 	ASSERT_FALSE(fh.fired([&fault_value](const uint64_t v) { fault_value = v; }));
 	ASSERT_EQ(0, fault_value);
 	ASSERT_EQ(0, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that the verison of fired() that takes a function which accepts
 * both the string and uint64, when the fault handler is enabled, invokes the
 * funciton with the expected arguments and updates the internal counters
 * appropriately.
 */
TEST(fault_handler_test, fired_string_uint64_when_enabled_increments_fired_count)
{
	const std::string fault_string = "yum";
	const uint64_t fault_uint64 = 1337;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(true);
 	fh.set_fault_string(fault_string);
 	fh.set_fault_uint64(fault_uint64);

	std::string fault_value_string;
	uint64_t fault_value_uint64 = 0;

 	ASSERT_TRUE(fh.fired(
		[&fault_value_string, &fault_value_uint64](const std::string& s,
		                                           const uint64_t v)
		{
			fault_value_string = s;
			fault_value_uint64 = v;
		}
	));
 	ASSERT_EQ(fault_string, fault_value_string);
 	ASSERT_EQ(fault_uint64, fault_value_uint64);
 	ASSERT_EQ(1, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that the verison of fired() that takes a function which accepts
 * both the string and uint64, when the fault handler is disabled, does not
 * invoke the funciton with the expected arguments and does not update the
 * the fired count.
 */
TEST(fault_handler_test, fired_string_uint64_when_disabled_increments_fired_count)
{
	const std::string fault_string = "yum";
	const uint64_t fault_uint64 = 1337;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(false);
 	fh.set_fault_string(fault_string);
 	fh.set_fault_uint64(fault_uint64);

	std::string fault_value_string;
	uint64_t fault_value_uint64 = 0;

 	ASSERT_FALSE(fh.fired(
		[&fault_value_string, &fault_value_uint64](const std::string& s,
		                                           const uint64_t v)
		{
			fault_value_string = s;
			fault_value_uint64 = v;
		}
	));
 	ASSERT_EQ("", fault_value_string);
 	ASSERT_EQ(0, fault_value_uint64);
 	ASSERT_EQ(0, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should fire, fired(function) returns true, invokes
 * the function, and increments the fired and hit counts.
 */
TEST(fault_handler_test, fired_function_when_enabled_increments_fired_count)
{
	bool fired = false;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(true);

 	ASSERT_TRUE(fh.fired([&fired](){ fired = true; }));
 	ASSERT_TRUE(fired);
 	ASSERT_EQ(1, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that when a fault should not fire, fired(function) returns false,
 * does not invoke the function, does not increment the fired count,
 * but does increment the hit count.
 */
TEST(fault_handler_test, fired_function_when_disables_does_not_increment_fired_count)
{
	bool fired = false;
 	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

 	fh.set_enabled(false);

 	ASSERT_FALSE(fh.fired([&fired](){ fired = true; }));
 	ASSERT_FALSE(fired);
 	ASSERT_EQ(0, fh.get_fired_count());
 	ASSERT_EQ(1, fh.get_hit_count());
}

/**
 * Ensure that fault_mode_to_string(fault_mode::ALWAYS) returns "ALWAYS".
 */
TEST(fault_handler_test, fault_mode_to_string_ALWAYS)
{
 	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;

 	ASSERT_EQ("ALWAYS", fault_handler::fault_mode_to_string(mode));
}

/**
 * Ensure that fault_mode_to_string(fault_mode::ONE_SHOT) returns "ONE_SHOT".
 */
TEST(fault_handler_test, fault_mode_to_string_ONE_SHOT)
{
 	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;

 	ASSERT_EQ("ONE_SHOT", fault_handler::fault_mode_to_string(mode));
}

/**
 * Ensure that fault_mode_to_string(fault_mode::PROBABILITY) returns "PROBABILITY".
 */
TEST(fault_handler_test, fault_mode_to_string_PROBABILITY)
{
 	const fault_handler::fault_mode mode = fault_handler::fault_mode::PROBABILITY;

 	ASSERT_EQ("PROBABILITY", fault_handler::fault_mode_to_string(mode));
}

/**
 * Ensure that fault_mode_to_string(fault_mode::AFTER_N) returns "AFTER_N"
 */
TEST(fault_handler_test, fault_mode_to_string_AFTER_N)
{
 	const fault_handler::fault_mode mode = fault_handler::fault_mode::AFTER_N;

 	ASSERT_EQ("AFTER_N", fault_handler::fault_mode_to_string(mode));
}

/**
 * Ensure that fault_mode_to_string(invalid-value) returns "UNKNOWN"
 */
TEST(fault_handler_test, fault_mode_to_string_UNKNOWN)
{
 	const fault_handler::fault_mode mode =
		static_cast<fault_handler::fault_mode>(5000);

 	ASSERT_EQ("UNKNOWN", fault_handler::fault_mode_to_string(mode));
}

/**
 * Ensure that fault_mode_from_string("ALWAYS") returns fault_mode::ALWAYS.
 */
TEST(fault_handler_test, fault_mode_from_string_ALWAYS)
{
	const std::string mode = "ALWAYS";

	ASSERT_EQ(fault_handler::fault_mode::ALWAYS,
	          fault_handler::fault_mode_from_string(mode));
}

/**
 * Ensure that fault_mode_from_string("ONE_SHOT") returns fault_mode::ONE_SHOT.
 */
TEST(fault_handler_test, fault_mode_from_string_ONE_SHOT)
{
	const std::string mode = "ONE_SHOT";

	ASSERT_EQ(fault_handler::fault_mode::ONE_SHOT,
	          fault_handler::fault_mode_from_string(mode));
}

/**
 * Ensure that fault_mode_from_string("PROBABILITY") returns fault_mode::PROBABILITY.
 */
TEST(fault_handler_test, fault_mode_from_string_PROBABILITY)
{
	const std::string mode = "PROBABILITY";

	ASSERT_EQ(fault_handler::fault_mode::PROBABILITY,
	          fault_handler::fault_mode_from_string(mode));
}

/**
 * Ensure that fault_mode_from_string("AFTER_N") returns fault_mode::AFTER_N.
 */
TEST(fault_handler_test, fault_mode_from_string_AFTER_N)
{
	const std::string mode = "AFTER_N";

	ASSERT_EQ(fault_handler::fault_mode::AFTER_N,
	          fault_handler::fault_mode_from_string(mode));
}

/**
 * Ensure that fault_mode_from_string(invalid-value) returns fault_mode::ALWAYS.
 */
TEST(fault_handler_test, fault_mode_from_string_INVALID)
{
	const std::string mode = "INVALID";

	ASSERT_EQ(fault_handler::fault_mode::ALWAYS,
	          fault_handler::fault_mode_from_string(mode));
}

/**
 * Ensure that clear_counters() resets the fired_count and hit_count to 0.
 */
TEST(fault_handler_test, clear_counters)
{
	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_enabled(true);

	ASSERT_TRUE(fh.fired());
	ASSERT_TRUE(fh.fired());

	fh.clear_counters();

	ASSERT_EQ(0, fh.get_fired_count());
 	ASSERT_EQ(0, fh.get_hit_count());
}

//------------------------------------------------------------------------------
//-- fault_mode::ALWAYS Tests
//------------------------------------------------------------------------------

/**
 * Ensure that fired() always returns false when the fault_handler is disabled
 * in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_disabled_fired)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_FALSE(fh.fired());
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}
 
/**
 * Ensure that fired() always returns true when the fault_handler is enabled
 * in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_enabled_fired)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(true);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_TRUE(fh.fired());
	}
	ASSERT_EQ(iterations, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) always leaves the string unmodified when
 * the fault_handler is disabled in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_disabled_fired_string)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;
	const std::string fault_string = "some fault string";

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_string(fault_string);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		std::string fault_value;

		ASSERT_FALSE(fh.fired([&fault_value](const std::string& s) { fault_value = s; }));

		ASSERT_EQ("", fault_value);
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) always updates the parameter when
 * the fault_handler is enabled in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_enabled_fired_string)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;
	const std::string fault_string = "some fault string";

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_string(fault_string);
	fh.set_enabled(true);

	for(size_t i = 0; i < iterations; ++i)
	{
		std::string fault_value;

		ASSERT_TRUE(fh.fired([&fault_value](const std::string& s) { fault_value = s; }));

		ASSERT_EQ(fault_string, fault_value);
	}

	ASSERT_EQ(iterations, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(uint64) always leaves the uint64 unmodified when
 * the fault_handler is disabled in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_disabled_fired_uint64)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;
	const uint64_t fault_uint64 = 112233;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_uint64(fault_uint64);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		uint64_t fault_value = 0;

		ASSERT_FALSE(fh.fired([&fault_value](uint64_t v) { fault_value = v; }));
		ASSERT_EQ(0, fault_value);
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(uint64) always updates the parameter when
 * the fault_handler is enabled in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_enabled_fired_uint64)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;
	const uint64_t fault_uint64 = 112233;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_uint64(fault_uint64);
	fh.set_enabled(true);

	for(size_t i = 0; i < iterations; ++i)
	{
		uint64_t fault_value = 0;

		ASSERT_TRUE(fh.fired([&fault_value](uint64_t v) { fault_value = v; }));
		ASSERT_EQ(fault_uint64, fault_value);
	}

	ASSERT_EQ(iterations, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(function) never calls the function when the fault_handler
 * is disabled in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_disabled_fired_function)
{
	const size_t iterations = 1000;
	size_t invoke_count = 0;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_FALSE(fh.fired([&invoke_count]() { ++invoke_count; } ));
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(0, invoke_count);
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(function) always calls the function when the fault_handler
 * is enabled in ALWAYS mode.
 */
TEST(fault_handler_test, alwaysEnabledMode_enabled_fired_function)
{
	const size_t iterations = 1000;
	size_t invoke_count = 0;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ALWAYS;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(true);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_TRUE(fh.fired([&invoke_count]() { ++invoke_count; } ));
	}

	ASSERT_EQ(iterations, fh.get_fired_count());
	ASSERT_EQ(iterations, invoke_count);
	ASSERT_EQ(iterations, fh.get_hit_count());
}

//------------------------------------------------------------------------------
//-- fault_mode::ONE_SHOT Tests
//------------------------------------------------------------------------------

/**
 * Ensure that fired() always returns false when the fault_handler is disabled
 * in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_disabled_fired)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_FALSE(fh.fired());
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}
 
/**
 * Ensure that fired() returns true only on the first call when the
 * fault_handler is enabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_enabled_fired)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(true);

	ASSERT_TRUE(fh.fired());

	for(size_t i = 0; i < iterations - 1; ++i)
	{
		ASSERT_FALSE(fh.fired());
	}

	ASSERT_EQ(1, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) always leaves the string unmodified when
 * the fault_handler is disabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_disabled_fired_string)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;
	const std::string fault_string = "some fault string";

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_string(fault_string);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		std::string fault_value;

		ASSERT_FALSE(fh.fired([&fault_value](const std::string& v) { fault_value = v; } ));

		ASSERT_EQ("", fault_value);
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) updates the parameter only on the first call
 * when the fault_handler is enabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_enabled_fired_string)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;
	const std::string fault_string = "some fault string";

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_string(fault_string);
	fh.set_enabled(true);

	{
		std::string fault_value;

		ASSERT_TRUE(fh.fired([&fault_value](const std::string& v) { fault_value = v; } ));
		ASSERT_EQ(fault_string, fault_value);
	}

	for(size_t i = 0; i < iterations - 1; ++i)
	{
		std::string fault_value;

		ASSERT_FALSE(fh.fired([&fault_value](const std::string& v) { fault_value = v; } ));
		ASSERT_EQ("", fault_value);
	}

	ASSERT_EQ(1, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(uint64) always leaves the uint64 unmodified when
 * the fault_handler is disabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_disabled_fired_uint64)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;
	const uint64_t fault_uint64 = 112233;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_uint64(fault_uint64);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		uint64_t fault_value = 0;

		ASSERT_FALSE(fh.fired([&fault_value](uint64_t v) { fault_value = v; } ));

		ASSERT_EQ(0, fault_value);
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) updates the parameter only on the first call
 * when the fault_handler is enabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_enabled_fired_uint64)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;
	const uint64_t fault_uint64 = 112233;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_uint64(fault_uint64);
	fh.set_enabled(true);

	{
		uint64_t fault_value = 0;

		ASSERT_TRUE(fh.fired([&fault_value](uint64_t v) { fault_value = v; } ));

		ASSERT_EQ(fault_uint64, fault_value);
	}

	for(size_t i = 0; i < iterations - 1; ++i)
	{
		uint64_t fault_value = 0;

		ASSERT_FALSE(fh.fired([&fault_value](uint64_t v) { fault_value = v; } ));

		ASSERT_EQ(0, fault_value);
	}

	ASSERT_EQ(1, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(function) never calls the function when the fault_handler
 * is disabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_disabled_fired_function)
{
	const size_t iterations = 1000;
	size_t invoke_count = 0;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_FALSE(fh.fired([&invoke_count]() { ++invoke_count; } ));
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(0, invoke_count);
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(function) invokes the function only on the first call
 * when the fault_handler is enabled in ONE_SHOT mode.
 */
TEST(fault_handler_test, oneShotEnabledMode_enabled_fired_function)
{
	const size_t iterations = 1000;
	size_t invoke_count = 0;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::ONE_SHOT;

	auto fn = [&invoke_count]() {
		++invoke_count;
	};

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_enabled(true);

	ASSERT_TRUE(fh.fired(fn));
	ASSERT_EQ(1, invoke_count);

	for(size_t i = 0; i < iterations - 1; ++i)
	{
		ASSERT_FALSE(fh.fired(fn));
	}

	ASSERT_EQ(1, fh.get_fired_count());
	ASSERT_EQ(1, invoke_count);
	ASSERT_EQ(iterations, fh.get_hit_count());
}

//------------------------------------------------------------------------------
//-- fault_mode::PROBABILITY Tests
//------------------------------------------------------------------------------

/**
 * Ensure that fired() always returns false when the fault_handler is disabled
 * in PROBABILITY mode.
 */
TEST(fault_handler_test, probablityEnabledMode_disabled_fired)
{
	const uint8_t probablity = 39;
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::PROBABILITY;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_probability(probablity);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_FALSE(fh.fired());
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}
 
/**
 * Ensure that fired() returns true with the expected probability when the
 * fault_handler is enabled in PROBABILITY mode.
 */
TEST(fault_handler_test, probablityEnabledMode_enabled_fired)
{
	fault_handler::seed_random_generator();

	const uint8_t probablity = 39;
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::PROBABILITY;
	int fired_count = 0;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_probability(probablity);
	fh.set_enabled(true);

	for(size_t i = 0; i < iterations; ++i)
	{
		if(fh.fired())
		{
			++fired_count;
		}
	}

	// With the given probablity, the exact answer would be 390, but
	// since we're dealing with random numbers, the value will be off.
	// The 380 number is based on experimentation with the given
	// constant random number seed.
	ASSERT_EQ(380, fh.get_fired_count());
	ASSERT_EQ(380, fired_count);
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) always leaves the string unmodified when
 * the fault_handler is disabled in PROBABILITY mode.
 */
TEST(fault_handler_test, probablityEnabledMode_disabled_fired_string)
{
	const uint8_t probablity = 14;
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::PROBABILITY;
	const std::string fault_string = "some fault string";

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_string(fault_string);
	fh.set_fault_probability(probablity);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		std::string fault_value;

		ASSERT_FALSE(fh.fired([&fault_value](const std::string& v) { fault_value = v; } ));

		ASSERT_EQ("", fault_value);
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired(std::string) updates the parameter with the expected
 * probablity when the fault_handler is enabled in PROBABILITY mode.
 */
TEST(fault_handler_test, probablityEnabledMode_enabled_fired_string)
{
	fault_handler::seed_random_generator();

	const uint8_t probablity = 14;
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::PROBABILITY;
	const std::string fault_string = "some fault string";
	int fired_count = 0;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_fault_string(fault_string);
	fh.set_fault_probability(probablity);
	fh.set_enabled(true);

	for(size_t i = 0; i < iterations; ++i)
	{
		std::string fault_value;

		if(fh.fired([&fault_value, &fired_count](const std::string& v) { fault_value = v; } ))
		{
			++fired_count;
			ASSERT_EQ(fault_string, fault_value);
		}
	}

	// With the given probablity, the exact answer would be 140, but
	// since we're dealing with random numbers, the value will be off.
	// The 133 number is based on experimentation with the given
	// constant random number seed.
	ASSERT_EQ(133, fh.get_fired_count());
	ASSERT_EQ(133, fired_count);
	ASSERT_EQ(iterations, fh.get_hit_count());
}

// //------------------------------------------------------------------------------
// //-- fault_mode::AFTER_N Tests
// //------------------------------------------------------------------------------

/**
 * Ensure that fired() always returns false when the fault_handler is disabled
 * in AFTER_N mode.
 */
TEST(fault_handler_test, afterNMode_disabled_fired)
{
	const size_t iterations = 1000;
	const fault_handler::fault_mode mode = fault_handler::fault_mode::AFTER_N;
	const uint8_t n_count = 2;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_n_count(n_count);
	fh.set_enabled(false);

	for(size_t i = 0; i < iterations; ++i)
	{
		ASSERT_FALSE(fh.fired());
	}

	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(n_count, fh.get_n_count());
	ASSERT_EQ(iterations, fh.get_hit_count());
}

/**
 * Ensure that fired() returns false for the first N calls, then returns true
 * thereaftre when the fault_handler is enabled in AFTER_N mode.
 */
TEST(fault_handler_test, afterNMode_enabled_fired)
{
	const fault_handler::fault_mode mode = fault_handler::fault_mode::AFTER_N;
	const uint8_t n_count = 2;

	fault_handler fh(FILENAME, LINE, NAME, DESCRIPTION);

	fh.set_fault_mode(mode);
	fh.set_n_count(n_count);
	fh.set_enabled(true);

	ASSERT_FALSE(fh.fired());
	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(1, fh.get_hit_count());
	ASSERT_EQ(n_count - 1, fh.get_n_count());

	ASSERT_FALSE(fh.fired());
	ASSERT_EQ(0, fh.get_fired_count());
	ASSERT_EQ(2, fh.get_hit_count());
	ASSERT_EQ(n_count - 2, fh.get_n_count());

	ASSERT_TRUE(fh.fired());
	ASSERT_EQ(1, fh.get_fired_count());
	ASSERT_EQ(3, fh.get_hit_count());
	ASSERT_EQ(0, fh.get_n_count());

	ASSERT_TRUE(fh.fired());
	ASSERT_EQ(2, fh.get_fired_count());
	ASSERT_EQ(4, fh.get_hit_count());
	ASSERT_EQ(0, fh.get_n_count());
}

#endif /* defined(FAULT_INJECTION_ENABLED) */
