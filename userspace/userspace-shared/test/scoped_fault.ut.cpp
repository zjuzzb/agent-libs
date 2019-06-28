/**
 * @file
 *
 * Unit tests for scoped_fault.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "fault_handler.h"
#include "scoped_fault.h"
#include <gtest.h>

using userspace_shared::fault_handler;
using test_helpers::scoped_fault;

/**
 * Ensure that if we give a fault name that does not exist, the constructor
 * for scoped_fault will throw a runtime_error.
 */
TEST(scoped_fault_test, non_existant_name_throws_exception)
{
	ASSERT_THROW(scoped_fault f("this-fault-does-not-exist"),
	             std::runtime_error);
}

/**
 * Ensure that a scoped_fault_handler will save the state of the named fault
 * on construction and restore it on destruction.
 */
TEST(scoped_fault_test, saves_on_construction_restores_on_destruction)
{
	fault_handler fh("filename.cpp",
	                 42,
	                 "test.scoped_fault_test.handler",
	                 "test handler");

	{
		fh.set_fault_string("taco");
		fh.set_fault_uint64(27);
		fh.set_fault_mode(fault_handler::fault_mode::PROBABILITY);
		fh.set_enabled(true);
		fh.set_fault_probability(100);
		fh.set_n_count(5);

		fh.fired();
		fh.fired();

		scoped_fault fault_state("test.scoped_fault_test.handler");

		fh.set_fault_string("bell");
		fh.set_fault_uint64(72);
		fh.set_fault_mode(fault_handler::fault_mode::ONE_SHOT);
		fh.set_enabled(false);
		fh.set_fault_probability(52);
		fh.set_n_count(10);
	}

	ASSERT_EQ("taco", fh.get_fault_string());
	ASSERT_EQ(27, fh.get_fault_uint64());
	ASSERT_EQ(fault_handler::fault_mode::PROBABILITY, fh.get_fault_mode());
	ASSERT_TRUE(fh.is_enabled());
	ASSERT_EQ(100, fh.get_fault_probability());
	ASSERT_EQ(5, fh.get_n_count());
	ASSERT_EQ(2, fh.get_fired_count());
	ASSERT_EQ(2, fh.get_hit_count());

}
