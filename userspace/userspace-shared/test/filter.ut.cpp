/**
 * @file
 *
 * Unit tests for filter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include <gtest.h>
#include "base_filter.h"

class filter_args {
public:
	filter_args(std::string foo,
		    uint64_t bar)
		: m_foo(foo),
		  m_bar(bar)
	{
	}

	std::string m_foo;
	uint64_t m_bar;

	bool operator==(const filter_args& other) const
	{
		return m_foo == other.m_foo && m_bar == other.m_bar;
	}
};

TEST(filter_test, all_filter)
{
	all_filter<filter_args> my_filter(false);
	all_filter<filter_args> my_filter_exclude(true);

	filter_args my_args("abc123", 123456);

	bool exclude = true;
	bool high_priority = true;
	std::string reason;
	bool matches = my_filter.matches(my_args, exclude, high_priority, reason);

	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, false);
	EXPECT_EQ(reason, "all");

	exclude = false;
	high_priority = true;
	matches = my_filter_exclude.matches(my_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, false);
}

TEST(filter_test, equal_filter)
{
	filter_args my_args("abc123", 123456);

	equal_filter<filter_args> my_filter(false, my_args);
	equal_filter<filter_args> my_filter_exclude(true, my_args);

	filter_args same_args("abc123", 123456);
	EXPECT_EQ(same_args == my_args, true);
	filter_args different_args("abc124", 133456);
	EXPECT_EQ(different_args == my_args, false);

	bool exclude = true;
	bool high_priority = false;
	std::string reason;
	bool matches = my_filter.matches(same_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "equality match");
	matches = my_filter.matches(different_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	exclude = false;
	high_priority = false;
	matches = my_filter_exclude.matches(same_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, true);
}

TEST(filter_test, regex_filter)
{
	regex_filter<std::string> my_filter(false,
					    "^hellothere?$",
					    [](const std::string& arg)->const std::string&{ return arg; });
	regex_filter<std::string> my_filter_exclude(true,
						    "^hellothere?$",
						    [](const std::string& arg)->const std::string&{ return arg; });

	bool exclude = true;
	bool high_priority = false;
	std::string reason;
	bool matches = my_filter.matches("hellothere", exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "hellothere matches regex ^hellothere?$");
	matches = my_filter.matches("hellother", exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	matches = my_filter.matches("heallother", exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	exclude = false;
	high_priority = false;
	matches = my_filter_exclude.matches("hellother", exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, true);
}

TEST(filter_test, wildcard_filter)
{
	wildcard_filter<std::string> my_filter(false,
					       "hellothere?",
					       [](const std::string& arg)->const std::string&{ return arg;});
	wildcard_filter<std::string> my_filter_exclude(true,
						       "hellothere?",
						       [](const std::string& arg)->const std::string&{ return arg;});

	bool exclude = true;
	bool high_priority = false;
	std::string reason;
	bool matches = my_filter.matches("hellothere1", exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "hellothere1 matches wildcard hellothere?");
	matches = my_filter.matches("heallother", exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	exclude = false;
	high_priority = false;
	matches = my_filter_exclude.matches("hellothere2", exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, true);
}

TEST(filter_test, priority_filter)
{
	filter_args my_args_1("hellothere", 1);
	filter_args my_args_2("goodbye!", 1);
	filter_args my_args_3("hello again", 1);

	priority_filter<filter_args> my_filter({
		std::make_shared<equal_filter<filter_args>>(false, my_args_1),
		std::make_shared<equal_filter<filter_args>>(true, my_args_2),
		std::make_shared<equal_filter<filter_args>>(false, my_args_3)
	});

	bool exclude = true;
	bool high_priority = false;
	std::string reason;
	bool matches = my_filter.matches(my_args_1, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "equality match");
	
	high_priority = false;
	matches = my_filter.matches(my_args_2, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "equality match");

	high_priority = false;
	matches = my_filter.matches(my_args_3, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "equality match");

	filter_args different_args("abc124", 133456);
	matches = my_filter.matches(different_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	// double check the rule num api
	uint32_t rule_num;
	matches = my_filter.matches(my_args_1, exclude, high_priority, reason, rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(rule_num, 0);
	matches = my_filter.matches(my_args_2, exclude, high_priority, reason, rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(rule_num, 1);
}

TEST(filter_test, and_filter)
{
	filter_args my_args_1("abc", 123);
	filter_args my_args_2("abc", 1233);

	and_filter<filter_args> my_filter(false,
        { 
		std::make_shared<all_filter<filter_args>>(false),
		std::make_shared<equal_filter<filter_args>>(false, my_args_1),
	});

	bool exclude = true;
	bool high_priority = true;
	std::string reason;
	bool matches = my_filter.matches(my_args_1, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, false);
	EXPECT_EQ(reason, "and filter matches:all;equality match;");
	
	matches = my_filter.matches(my_args_2, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	and_filter<filter_args> my_filter_exclude(true,
        { 
		std::make_shared<all_filter<filter_args>>(false),
		std::make_shared<equal_filter<filter_args>>(false, my_args_1),
	});

	exclude = true;
	high_priority = true;
	matches = my_filter_exclude.matches(my_args_1, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, false);

	and_filter<filter_args> my_filter_high_priority(true,
        { 
		std::make_shared<equal_filter<filter_args>>(false, my_args_1),
		std::make_shared<equal_filter<filter_args>>(false, my_args_1),
	});

	exclude = true;
	high_priority = false;
	matches = my_filter_high_priority.matches(my_args_1, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(high_priority, true);

}

TEST(filter_test, combo_test)
{
	priority_filter<filter_args> my_filter({
		std::make_shared<equal_filter<filter_args>>(false, filter_args("1", 1)),
		std::make_shared<and_filter<filter_args>>(true, std::list<std::shared_ptr<base_filter<filter_args>>>({
			std::make_shared<regex_filter<filter_args>>(false, "ab?", [](const filter_args& arg)->const std::string&{ return arg.m_foo; }),
			std::make_shared<regex_filter<filter_args>>(false, "a?b", [](const filter_args& arg)->const std::string&{ return arg.m_foo; })
		})),
		std::make_shared<regex_filter<filter_args>>(false, "qwe", [](const filter_args& arg)->const std::string&{ return arg.m_foo; }),
		std::make_shared<all_filter<filter_args>>(true)
	});

	bool exclude = false;
	bool high_priority = false;
	bool matches = false;
	std::string reason;
	uint32_t rule_num;
	
	matches = my_filter.matches(filter_args("1", 1),
				    exclude,
				    high_priority,
				    reason,
				    rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(reason, "equality match");
	EXPECT_EQ(rule_num, 0);

	matches = my_filter.matches(filter_args("ab", 1),
				    exclude,
				    high_priority,
				    reason,
				    rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(reason, "and filter matches:ab matches regex ab?;ab matches regex a?b;");
	EXPECT_EQ(rule_num, 1);

	matches = my_filter.matches(filter_args("qwe", 1),
				    exclude,
				    high_priority,
				    reason,
				    rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(reason, "qwe matches regex qwe");
	EXPECT_EQ(rule_num, 2);

	matches = my_filter.matches(filter_args("123", 1),
				    exclude,
				    high_priority,
				    reason,
				    rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(high_priority, false);
	EXPECT_EQ(exclude, true);
	EXPECT_EQ(reason, "all");
	EXPECT_EQ(rule_num, 3);
}
