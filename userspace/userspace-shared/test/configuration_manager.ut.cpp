/**
 * @file
 *
 * Unit tests for configuration_manager.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "configuration_manager.h"
#include "scoped_temp_file.h"
#include "type_config.h"
#include <fstream>
#include <gtest.h>

class configuration_manager_test : public testing::Test
{
public:
	static void SetUpTestCase()
	{
		m_config_file = new test_helpers::scoped_temp_file();
		std::ofstream out(m_config_file->get_filename().c_str());

		out << "key1: true" << std::endl;
		out << "key2: 123" << std::endl;

	}

	static void TearDownTestCase()
	{
		delete m_config_file;
		m_config_file = nullptr;
	}

protected:
	const std::string& get_conf_file() const
	{
		return m_config_file->get_filename();
	}

private:
	static test_helpers::scoped_temp_file* m_config_file;
};
test_helpers::scoped_temp_file* configuration_manager_test::m_config_file;

/**
 * Ensure that type_config%s get registered with the configuration manager
 * on construction.
 */
TEST_F(configuration_manager_test, register_config)
{
	type_config<bool> c(true, "description", "key");
	ASSERT_TRUE(configuration_manager::is_registered(&c));
}

/**
 * Ensure that type_config%s get deregistered with the configuration manager
 * on destruction.
 */
TEST_F(configuration_manager_test, deregister_config)
{
	type_config<bool>* c_p;

	{
		type_config<bool> c(true, "description", "key");
		c_p = &c;
	}

	ASSERT_FALSE(configuration_manager::is_registered(c_p));
}

/**
 * Ensure that init_config() init's all registered config.
 */
TEST_F(configuration_manager_test, init_config)
{
	const bool expected_c1 = true;
	const bool default_c1 = !expected_c1;

	const uint16_t expected_c2 = 123;
	const uint16_t default_c2 = ~expected_c2;

	type_config<bool> c1(default_c1, "description", "key1");
	type_config<uint16_t> c2(default_c2, "description", "key2");

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	configuration_manager::init_config(config_yaml);

	ASSERT_EQ(expected_c1, c1.get());
	ASSERT_EQ(expected_c2, c2.get());
}

/**
 * Ensure that print_config() writes all the configs to the given handler
 * function.
 */
TEST_F(configuration_manager_test, print_config)
{
	const bool expected_c1 = true;
	const bool default_c1 = !expected_c1;

	const uint16_t expected_c2 = 123;
	const uint16_t default_c2 = ~expected_c2;

	type_config<bool> c1(default_c1, "description", "key1");
	type_config<uint16_t> c2(default_c2, "description", "key2");
	std::string log_output;

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	configuration_manager::print_config([&log_output](const std::string& log)
		{
			log_output += log + "\n";
		});

	// configuration_manager doesn't make any guarantees about what order
	// the configs will be logged, so we'll just make sure the configs
	// are in the output.
	ASSERT_NE(log_output.find(c1.to_string()), std::string::npos);
	ASSERT_NE(log_output.find(c2.to_string()), std::string::npos);
}
