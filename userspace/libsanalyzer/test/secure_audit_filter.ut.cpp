#include "scoped_configuration.h"
#include <gtest.h>
#include <memory>
#include <scoped_config.h>
#include <secure_audit_filter.h>

#define ONE_SECOND_IN_NS 1000000000LL

namespace
{
uint64_t seconds_to_ns(const int seconds)
{
    return ((uint64_t) seconds * ONE_SECOND_IN_NS);
}
}

TEST(secure_audit_filter_test, basic_cmd_filter_disabled)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", false);
	test_helpers::scoped_config<int> threshold_secure_audit_filter("secure_audit_filter.commands_threshold", 2);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, 0));

	delete saf;
}

TEST(secure_audit_filter_test, basic_cmd_filter)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", true);
	test_helpers::scoped_config<int> threshold_secure_audit_filter("secure_audit_filter.commands_threshold", 2);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, 0));
	ASSERT_TRUE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, 0));

	delete saf;
}

TEST(secure_audit_filter_test, basic_cmd_conn_file_filter)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", true);
	test_helpers::scoped_config<int> threshold_secure_audit_filter("secure_audit_filter.commands_threshold", 2);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, 0));

	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, 0));
	ASSERT_TRUE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, 0));

	ASSERT_TRUE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, 0));
	ASSERT_TRUE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, 0));

	delete saf;
}

TEST(secure_audit_filter_test, basic_conn_file_only)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", true);
	test_helpers::scoped_config<int> threshold_secure_audit_filter_conn("secure_audit_filter.connections_threshold", 2);
	test_helpers::scoped_config<int> threshold_secure_audit_filter_file("secure_audit_filter.files_threshold", 2);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, 0));
	ASSERT_TRUE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, 0));

	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, 0));
	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, 0));
	ASSERT_TRUE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, 0));

	delete saf;
}

TEST(secure_audit_filter_test, basic_cmd_filter_slide_window)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", true);
	test_helpers::scoped_config<int> threshold_secure_audit_filter("secure_audit_filter.commands_threshold", 2);
	test_helpers::scoped_config<int> sw_secure_audit_filter("secure_audit_filter.sliding_window", 20);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, seconds_to_ns(0)));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, seconds_to_ns(1)));
	ASSERT_TRUE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, seconds_to_ns(3)));

	// next slide window
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, seconds_to_ns(21)));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, seconds_to_ns(22)));
	ASSERT_TRUE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("a"), 1, seconds_to_ns(23)));

	delete saf;
}

TEST(secure_audit_filter_test, basic_cmd_conn_file_filter_window)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", true);
	test_helpers::scoped_config<int> threshold_secure_audit_filter("secure_audit_filter.commands_threshold", 2);
	test_helpers::scoped_config<int> sw_secure_audit_filter("secure_audit_filter.sliding_window", 10);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));

	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_TRUE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, seconds_to_ns(0)));

	ASSERT_TRUE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_TRUE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));

	// next slide window
	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));

	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_FALSE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_TRUE(saf->discard_activity_audit_command(std::string("cid"), std::string("cwd"), std::string("ps -el"), std::string("ps"), 1, seconds_to_ns(11)));

	ASSERT_TRUE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_TRUE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));

	delete saf;
}

TEST(secure_audit_filter_test, basic_conn_file_only_window)
{
	test_helpers::scoped_config<bool> enable_secure_audit_filter("secure_audit_filter.enabled", true);
	test_helpers::scoped_config<int> threshold_secure_audit_filter_conn("secure_audit_filter.connections_threshold", 2);
	test_helpers::scoped_config<int> threshold_secure_audit_filter_file("secure_audit_filter.files_threshold", 2);
	test_helpers::scoped_config<int> sw_secure_audit_filter("secure_audit_filter.sliding_window", 10);

	secure_audit_filter* saf = new secure_audit_filter();

	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_TRUE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));

	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));
	ASSERT_TRUE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(0)));

	//next slide window
	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_FALSE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_TRUE(saf->discard_activity_audit_connection(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));

	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_FALSE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));
	ASSERT_TRUE(saf->discard_activity_audit_file(std::string("cid"), std::string("ps"), 1, seconds_to_ns(11)));

	delete saf;
}