#include <gtest.h>
#include <cgroup_list_counter.h>

TEST(cgroup_list_counter_test, basic)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(8, counter("0-5,8,14"));
	ASSERT_EQ(1, counter("5"));
	ASSERT_EQ(6, counter("9-14"));
}

TEST(cgroup_list_counter_test, invalid_value)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter(""));
	ASSERT_EQ(-1, counter(",1"));
}

TEST(cgroup_list_counter_test, invalid_range_missing_number)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("-5,8,14"));
	ASSERT_EQ(-1, counter("1,-5,8,14"));
	ASSERT_EQ(-1, counter("1,4-,14"));
	ASSERT_EQ(-1, counter("1,4-"));
}

TEST(cgroup_list_counter_test, invalid_range_double_dash)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("1,4-5-6,14"));
}

TEST(cgroup_list_counter_test, invalid_range_wrong_order)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("1,6-5,14"));
}

TEST(cgroup_list_counter_test, not_a_number)
{
	libsinsp::cgroup_list_counter counter;
	ASSERT_EQ(-1, counter("1,5-a,14"));
}

