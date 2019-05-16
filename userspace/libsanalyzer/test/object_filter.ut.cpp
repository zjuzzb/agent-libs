/**
 * @file
 *
 * Unit tests for object filter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include <gtest.h>
#include "base_filter.h"
#include "sinsp.h"
#include "analyzer_thread.h"
#include "object_filter.h"
#include "scoped_temp_file.h"

class test_helper
{
public:
	static void set_listening_ports(thread_analyzer_info* ainfo, std::set<uint16_t>& ports)
	{
		ainfo->m_listening_ports = std::unique_ptr<std::set<uint16_t>>(new std::set<uint16_t>(ports));
	}

	static void clear_app_check(thread_analyzer_info* ainfo)
	{
		ainfo->m_app_checks_found.clear();
	}

	static void insert_app_check(thread_analyzer_info* ainfo, std::string value)
	{
		ainfo->m_app_checks_found.insert(value);
	}

	static std::string filter_name(const object_filter& filter)
	{
		return filter.m_name;
	}
};

TEST(object_filter_test, port_filter_single_against_range)
{
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info(); 
	std::set<uint16_t> ports = {12};
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);
	object_filter_args args(&tinfo, NULL, NULL, NULL);

	std::set<uint16_t> ports2 = {};
	port_filter my_filter({object_filter_config::port_filter_rule(true, false, 0, 12, ports2)});

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";

	// 12 is in range 0->12
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "1 ports match: 12");

	matches = true;
	// 12 is not in range 0->11
	port_filter my_filter2({object_filter_config::port_filter_rule(true, false, 0, 11, ports2)});
	matches = my_filter2.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	matches = false;
	// 12 is in range 12->20
	port_filter my_filter3({object_filter_config::port_filter_rule(true, false, 12, 20, ports2)});
	matches = my_filter3.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);

	delete tinfo.m_ainfo;
}

TEST(object_filter_test, port_filter_single_against_set)
{
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info(); 
	std::set<uint16_t> ports = {12};
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);
	object_filter_args args(&tinfo, NULL, NULL, NULL);

	std::set<uint16_t> ports2 = {10, 20};

	bool matches = true;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	// 12 is not in set 10, 20
	port_filter my_filter4({object_filter_config::port_filter_rule(true, true, 0, 0, ports2)});
	matches = true;
	matches = my_filter4.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	ports2.insert(12);
	// 12 is in set 10, 12, 20
	port_filter my_filter5({object_filter_config::port_filter_rule(true, true, 0, 0, ports2)});
	matches = false;
	reason = "";
	matches = my_filter5.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(reason, "1 ports match: 12");

	delete tinfo.m_ainfo;
}

TEST(object_filter_test, port_filter_multiple_against_range)
{
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info(); 
	std::set<uint16_t> ports = {12, 20};
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);
	object_filter_args args(&tinfo, NULL, NULL, NULL);

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	std::set<uint16_t> ports2 = {};
	// one of 12, 20 is in range 0->12
	port_filter my_filter({object_filter_config::port_filter_rule(true, false, 0, 12, ports2)});
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "1 ports match: 12");

	std::set<uint16_t> ports3 = {10, 20, 12};
	// one of 10, 12, 20 is in range 20->100
	port_filter my_filter6({object_filter_config::port_filter_rule(true, false, 20, 100, ports3)});
	matches = my_filter6.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "1 ports match: 20");

	// two of 10, 12, 20 is in range 12->20
	port_filter my_filter3({object_filter_config::port_filter_rule(true, false, 12, 20, ports3)});
	matches = my_filter3.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "2 ports match: 12");

	// none of 10, 12, 20 is in range 0->11
	port_filter my_filter2({object_filter_config::port_filter_rule(true, false, 0, 11, ports2)});
	matches = my_filter2.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	delete tinfo.m_ainfo;
}

TEST(object_filter_test, port_filter_multiple_against_set)
{
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info(); 
	std::set<uint16_t> ports = {12, 20};
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);
	object_filter_args args(&tinfo, NULL, NULL, NULL);

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	std::set<uint16_t> ports2 = {10, 12, 20};
	// 2 of 12, 20 are in set 10, 12, 20
	port_filter my_filter5({object_filter_config::port_filter_rule(true, true, 0, 0, ports2)});
	matches = my_filter5.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(reason, "2 ports match: 12");

	std::set<uint16_t> ports3 = {10};
	// 0 of 12, 20 are in set 10
	port_filter my_filter7({object_filter_config::port_filter_rule(true, true, 0, 0, ports3)});
	matches = my_filter7.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	delete tinfo.m_ainfo;
}

TEST(object_filter_test, port_filter_include_exclude)
{	
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info(); 
	std::set<uint16_t> ports = {25,75,76,81,82};
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);
	object_filter_args args(&tinfo, NULL, NULL, NULL);

	// tests with multiple rules filter and exclude
	// -include range 0-50: 51 ports will match
	// -exclude set 25, 75, 81: none of these will match from now on
	// -exclude range 40-80: blocks the rest of the ports from matching in this range
	// -include set 25, 75, 76, 81, 82: 25 is already included, rest are blocked except 82
	std::set<uint16_t> ports2 = {25,75,81};
	port_filter my_filter8({object_filter_config::port_filter_rule(true, false, 0, 50, ports2),
			        object_filter_config::port_filter_rule(false, true, 0, 0, ports2),
			        object_filter_config::port_filter_rule(false, false, 40, 80, ports),
			        object_filter_config::port_filter_rule(true, true, 0, 0, ports)});

	for(int i=0; i<100; i++)
	{
		ports.insert(i);
	}
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);
	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	matches = my_filter8.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "52 ports match: 0"); //51 from rule 1, plus 1 from rule 4

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	std::set<uint16_t> ports3 = {};
	port_filter my_filter({object_filter_config::port_filter_rule(true, false, 0, 12, ports3)});
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	delete tinfo.m_ainfo;
}

TEST(object_filter_test, process_name_filter)
{	
	process_name_filter my_filter("process?name");

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	sinsp_threadinfo tinfo;
	tinfo.m_comm = "process_name";
	object_filter_args args(&tinfo, NULL, NULL, NULL);
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "process_name matches wildcard process?name");

	tinfo.m_comm = "not_a_process";
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);
}

TEST(object_filter_test, process_cmd_line_filter)
{
	process_cmd_line_filter my_filter("fo?");

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	sinsp_threadinfo tinfo;
	tinfo.m_exe = "barfo?baz";
	object_filter_args args(&tinfo, NULL, NULL, NULL);
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "arg_found: fo?");

	tinfo.m_exe = "something else";
	tinfo.m_args.push_back("foo");
	matches = false;
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);


	tinfo.m_args.clear();
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);
}

TEST(object_filter_test, container_name_filter)
{
	container_name_filter my_filter("container?name");

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	sinsp_container_info container;
	container.m_name = "container_name";
	object_filter_args args(NULL, NULL, &container, NULL);
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "container_name matches wildcard container?name");

	container.m_name = "not_a_container";
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);
}

TEST(object_filter_test, container_image_filter)
{
	container_image_filter my_filter("container?image");

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	sinsp_container_info container;
	container.m_image = "container_image";
	object_filter_args args(NULL, NULL, &container, NULL);
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "container_image matches wildcard container?image");

	container.m_image = "not_a_container";
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);
}

TEST(object_filter_test, container_label_filter)
{
	container_label_filter my_filter("some_label", "some?value");

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	sinsp_container_info container;
	container.m_labels.insert(std::pair<std::string, std::string>("some_label", "some_value"));
	object_filter_args args(NULL, NULL, &container, NULL);
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "some_label equals some?value");

	container.m_labels.clear();
	container.m_labels.insert(std::pair<std::string, std::string>("some_label", "somevalue"));
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	container.m_labels.clear();
	container.m_labels.insert(std::pair<std::string, std::string>("some_other_label", "somevalue"));
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);
}

TEST(object_filter_test, tag_filter)
{
	// left unimplemented due to lack of mock infrastructure state required to easily
	// simulate addition of tags
}

TEST(object_filter_test, app_check_filter)
{
	app_check_filter my_filter("some app?check");

	bool matches = false;
	bool exclude = true;
	bool high_priority = false;
	std::string reason = "";
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info;
	test_helper::insert_app_check(tinfo.m_ainfo, "some app check");
	object_filter_args args(NULL, &tinfo, NULL, NULL);
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(exclude, false);
	EXPECT_EQ(high_priority, true);
	EXPECT_EQ(reason, "found app check: some app?check");

	test_helper::clear_app_check(tinfo.m_ainfo);
	test_helper::insert_app_check(tinfo.m_ainfo, "some other app check");
	matches = my_filter.matches(args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	object_filter_args null_args(NULL, NULL, NULL, NULL);
	matches = my_filter.matches(null_args, exclude, high_priority, reason);
	EXPECT_EQ(matches, false);

	delete tinfo.m_ainfo;
}

// just make sure we don't die if you give a none filter
TEST(object_filter_test, none_test)
{
	object_filter my_filter("filter name");
	object_filter_config::filter_rule none_filter_rule ("name",
							    true,
							    {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::none,
												    "",
												    "",
												    {})},
							    object_filter_config::rule_config());

	std::vector<object_filter_config::filter_rule> rules{none_filter_rule};
	my_filter.set_rules(rules);

	bool matches = my_filter.matches(NULL, NULL, NULL, NULL, NULL, NULL);
	// an and filter with no conditions is always met
	EXPECT_EQ(matches, true);
}

// one for each, multi-condition rule, zero rule, exclude
TEST(object_filter_test, object_filter)
{
	object_filter my_filter("filter name");
	EXPECT_EQ(test_helper::filter_name(my_filter), "filter name");


	// create an array of one of each type of rule to ensure we set rules
	std::set<uint16_t> ports = {12};
	object_filter_config::filter_rule port_filter_rule("name",
							   true,
							   {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::port,
												   "",
												   "",
												   {object_filter_config::port_filter_rule(true, false, 0, 12, ports)})},
							   object_filter_config::rule_config());
	object_filter_config::filter_rule process_name_filter_rule("name",
								   true,
								   {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::process_name,
													   "",
													   "my_process_name",
													   {})},
								   object_filter_config::rule_config());
	object_filter_config::filter_rule process_cmd_line_filter_rule("name",
								       true,
								       {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::process_cmdline,
													       "",
													       "my_process_cmd_line",
													       {})},
								       object_filter_config::rule_config());
	object_filter_config::filter_rule container_name_filter_rule("name",
								     true,
								     {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::container_name,
													     "",
													     "my_container_name",
													     {})},
								     object_filter_config::rule_config());
	object_filter_config::filter_rule container_image_filter_rule("name",
								      true,
								      {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::container_image,
													      "",
													      "my_container_image",
													      {})},
								      object_filter_config::rule_config());
	object_filter_config::filter_rule container_label_filter_rule("name",
								      true,
								      {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::container_label,
													      "label",
													      "pattern",
													      {})},
								      object_filter_config::rule_config());
	object_filter_config::filter_rule tag_filter_rule("name",
							  true,
							  {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::tag,
												  "tag",
												  "pattern",
												  {})},
							  object_filter_config::rule_config());
	object_filter_config::filter_rule app_check_filter_rule("name",
								true,
								{object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::app_check_match,
													"",
													"app check",
													{})},
								object_filter_config::rule_config());
	object_filter_config::filter_rule all_filter_rule("name",
							  true,
							  {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::all,
												  "",
												  "",
												  {})},
							  object_filter_config::rule_config());

	std::vector<object_filter_config::filter_rule> rules{port_filter_rule,
							     process_name_filter_rule,
							     process_cmd_line_filter_rule,
							     container_name_filter_rule,
							     container_image_filter_rule,
							     container_label_filter_rule,
							     tag_filter_rule,
							     app_check_filter_rule,
							     all_filter_rule};

	my_filter.set_rules(rules);

	// now go through and check that each rule matches
	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info(); 
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);

	bool matches = false;
	bool generic_match = true;
	const object_filter_config::filter_rule* rule_num;
	matches = my_filter.matches(&tinfo, NULL, NULL, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::port);
	ports.clear();
	test_helper::set_listening_ports(tinfo.m_ainfo, ports);

	tinfo.m_comm = "my_process_name";
	matches = false;
	generic_match = true;
	matches = my_filter.matches(&tinfo, NULL, NULL, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::process_name);
	tinfo.m_comm = "other_process_name";

	tinfo.m_exe = "my_process_cmd_line";
	matches = false;
	generic_match = true;
	matches = my_filter.matches(&tinfo, NULL, NULL, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::process_cmdline);
	tinfo.m_comm = "other_process_name";

	sinsp_container_info container;
	container.m_name = "my_container_name";
	matches = false;
	generic_match = true;
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::container_name);
	container.m_name = "other_process_name";

	container.m_image = "my_container_image";
	matches = false;
	generic_match = true;
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::container_image);
	container.m_image = "other_process_name";

	container.m_labels.insert(std::pair<std::string, std::string>("label", "pattern"));
	matches = false;
	generic_match = true;
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::container_label);
	container.m_labels.clear();

	test_helper::insert_app_check(tinfo.m_ainfo, "app check");
	matches = false;
	generic_match = true;
	matches = my_filter.matches(NULL, &tinfo, NULL, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::app_check_match);
	test_helper::clear_app_check(tinfo.m_ainfo);

	matches = false;
	generic_match = true;
	matches = my_filter.matches(NULL, NULL, NULL, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, true);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::all);

	// create a filter with a combo rule and make sure it works
	object_filter_config::filter_rule combo_rule("name",
						     true,
						     {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::container_name,
											     "",
											     "my_container_name",
											     {}),
						     object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::container_image,
											    "",
											    "my_container_image",
											    {})},
						     object_filter_config::rule_config());


	std::vector<object_filter_config::filter_rule> combo_rules{combo_rule};
	my_filter.set_rules(combo_rules);
	container.m_name = "my_container_name";
	container.m_image = "my_container_image";
	matches = false;
	generic_match = true;
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::container_name);
	EXPECT_EQ(rule_num->m_cond[1].m_param_type, object_filter_config::filter_condition::param_type::container_image);
	container.m_image = "wrong image";
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, false);
	container.m_name = "wrong name";
	container.m_image = "my_container_image";
	matches = true;
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, false);

	// create a filter with no rules and make sure it works
	std::vector<object_filter_config::filter_rule> no_rules_just_right{};
	my_filter.set_rules(no_rules_just_right);
	matches = true;
	matches = my_filter.matches(NULL, NULL, NULL, NULL, NULL, NULL);
	EXPECT_EQ(matches, true);

	// create a filter with an exclude rule and make sure it works
	object_filter_config::filter_rule exclude_rule("name",
						       false,
						       {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::container_name,
											       "",
											       "my_container_name",
											       {})},
						       object_filter_config::rule_config());

	std::vector<object_filter_config::filter_rule> exclude_list{exclude_rule, all_filter_rule};
	my_filter.set_rules(exclude_list);

	container.m_name = "my_container_name";
	matches = true;
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, false);
	container.m_name = "other_container_name";
	matches = my_filter.matches(NULL, NULL, &container, NULL, &generic_match, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, true);

	delete tinfo.m_ainfo;
}

TEST(object_filter_test, register_annotations)
{
	std::map<std::string, std::string> option_map;
	std::map<std::string, std::string> tag_map;
	option_map.insert(std::make_pair<std::string, std::string>("option", "{register}"));
	object_filter_config::filter_rule filter_rule("name",
						      true,
						      {object_filter_config::filter_condition(object_filter_config::filter_condition::param_type::tag,
											      "register",
											      "",
											      {})},
						      object_filter_config::rule_config("{register}", true, "{register}", true, option_map, true, tag_map, true));

	std::vector<object_filter_config::filter_rule> rule_list{filter_rule};
	object_filter my_filter("my filter");
	my_filter.set_rules(rule_list);

	uint32_t cb_count = 0;
	my_filter.register_annotations([&](const std::string& arg){
					       EXPECT_EQ(arg, "register");
					       cb_count++;
				       });
	EXPECT_EQ(cb_count, 4);
}

TEST(object_filter_test, init_from_config)
{
	std::string yaml_string = R"(test_filter:
  - exclude:
      container.name: my_container_name
      container.image: my_container_image
  - include:
        all
)";

	object_filter_config::object_filter_config_data my_data("description", "test_filter");
	yaml_configuration config_yaml(yaml_string);
	ASSERT_EQ(0, config_yaml.errors().size());

	my_data.init(config_yaml);

	// validate rules created correctly
	EXPECT_EQ(my_data.get().size(), 2);
	EXPECT_EQ(my_data.get()[0].m_cond.size(), 2);
	EXPECT_EQ(my_data.get()[0].m_include, false);

	// this ordering is non-deterministic. We just care we get both conditions in
	// some order, so have to check both.
	if (my_data.get()[0].m_cond[0].m_param_type == object_filter_config::filter_condition::param_type::container_name)
	{
		EXPECT_EQ(my_data.get()[0].m_cond[0].m_pattern, "my_container_name");
		EXPECT_EQ(my_data.get()[0].m_cond[1].m_param_type, object_filter_config::filter_condition::param_type::container_image);
		EXPECT_EQ(my_data.get()[0].m_cond[1].m_pattern, "my_container_image");
	}
	else if (my_data.get()[0].m_cond[0].m_param_type == object_filter_config::filter_condition::param_type::container_image)
	{
		EXPECT_EQ(my_data.get()[0].m_cond[1].m_pattern, "my_container_name");
		EXPECT_EQ(my_data.get()[0].m_cond[1].m_param_type, object_filter_config::filter_condition::param_type::container_name);
		EXPECT_EQ(my_data.get()[0].m_cond[0].m_pattern, "my_container_image");
	}
	else
	{
		EXPECT_EQ(true, false);
	}

	EXPECT_EQ(my_data.get()[1].m_cond.size(), 1);
	EXPECT_EQ(my_data.get()[1].m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::all);
	EXPECT_EQ(my_data.get()[1].m_include, true);

	// validate we can make a filter and it works
	object_filter my_filter("my filter");
	my_filter.set_rules(my_data.get());

	sinsp_container_info container;
	container.m_name = "my_container_name";
	container.m_image = "my_container_image";
	bool matches = true;
	const object_filter_config::filter_rule* rule_num;
	matches = my_filter.matches(NULL, NULL, &container, NULL, NULL, &rule_num);
	EXPECT_EQ(matches, false);
	container.m_name = "other";
	container.m_image = "other";
	matches = my_filter.matches(NULL, NULL, &container, NULL, NULL, &rule_num);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(rule_num->m_cond[0].m_param_type, object_filter_config::filter_condition::param_type::all);
}

