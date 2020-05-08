/**
 * @file
 *
 * Unit tests for object filter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "analyzer_fd.h"
#include "configuration_manager.h"
#include "scoped_configuration.h"

#include <gtest.h>

using namespace test_helpers;

TEST(port_list_config, init)
{
	std::string yaml_string = R"(known_ports:
  - 23
  - 37
)";

	scoped_configuration config(yaml_string);
	EXPECT_TRUE(config.loaded());
	const port_list_config* known_ports = dynamic_cast<const port_list_config*>(
	    configuration_manager::instance().get_configuration_unit("known_ports"));
	ASSERT_NE(known_ports, nullptr);
	EXPECT_EQ(known_ports->value_to_string(), "Count: 2");
	EXPECT_TRUE(known_ports->get_value().test(23));
	EXPECT_TRUE(known_ports->get_value().test(37));
	EXPECT_FALSE(known_ports->get_value().test(5));
	EXPECT_FALSE(known_ports->get_value().test(84));
}
