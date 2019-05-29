/**
 * @file
 *
 * Unit tests for type_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "configuration_manager.h"
#include "scoped_temp_file.h"
#include "type_config.h"
#include "yaml_configuration.h"
#include <fstream>
#include <vector>
#include <gtest.h>

namespace
{

const bool DEFAULT_BOOL = true;
const std::string DEFAULT_DESCRIPTION = "some default description";
const std::vector<uint16_t> INT_VECTOR_VALUE = { 5, 7, 27 };
const int INT_12345_VALUE = 12345;

const char* bool_to_string(const bool value)
{
	return value ? "true" : "false";
}

} // end namespace

class type_config_test : public testing::Test
{
public:
	static void SetUpTestCase()
	{
		m_config_file = new test_helpers::scoped_temp_file();
		std::ofstream out(m_config_file->get_filename().c_str());

		// Output a raw string literal; all of the embedded newlines
		// get printed as well.
		out << R"config_string(
bool_true: true
bool_false: false

bool_nested:
  bool_true_nested: true
  bool_false_nested: false

bool_double_nested:
  bool_double_nested_sub:
    bool_true_double_nested: true
    bool_false_double_nested: false

some_string: "hello, world!"

int_12345: 12345

int_vector: [5, 7, 27]
)config_string";

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
test_helpers::scoped_temp_file* type_config_test::m_config_file;


TEST_F(type_config_test, key)
{
	const std::string key = "my_key";

	type_config<bool> some_config(DEFAULT_BOOL, DEFAULT_DESCRIPTION, key);

	ASSERT_EQ(key, some_config.get_key());
	ASSERT_EQ(key, some_config.get_key_string());
}

TEST_F(type_config_test, subkey)
{
	const std::string key = "my_key";
	const std::string subkey = "my_subkey";

	type_config<bool> some_config(DEFAULT_BOOL, DEFAULT_DESCRIPTION, key, subkey);

	ASSERT_EQ(key, some_config.get_key());
	ASSERT_EQ(subkey, some_config.get_subkey());
	ASSERT_EQ(key + "." + subkey, some_config.get_key_string());
}

TEST_F(type_config_test, subsubkey)
{
	const std::string key = "my_key";
	const std::string subkey = "my_subkey";
	const std::string subsubkey = "my_subsubkey";

	type_config<bool> some_config(DEFAULT_BOOL,
	                              DEFAULT_DESCRIPTION,
	                              key,
	                              subkey,
	                              subsubkey);

	ASSERT_EQ(key, some_config.get_key());
	ASSERT_EQ(subkey, some_config.get_subkey());
	ASSERT_EQ(subsubkey, some_config.get_subsubkey());
	ASSERT_EQ(key + "." + subkey + "." + subsubkey,
	          some_config.get_key_string());
}

TEST_F(type_config_test, description)
{
	const std::string description = "some unusual test description";
	const std::string key = "my_key";

	type_config<bool> some_config(DEFAULT_BOOL, description, key);

	ASSERT_EQ(description, some_config.get_description());
}

TEST_F(type_config_test, bool_to_string)
{
	const bool default_value = true;
	const std::string key = "my_key";
	const std::string expected_value = key + ": " + bool_to_string(default_value);

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

	ASSERT_EQ(expected_value, some_config.to_string());
}

TEST_F(type_config_test, uint16_to_string)
{
	const uint16_t default_value = 2589;
	const std::string key = "my_key";
	const std::string expected_value = key + ": " + std::to_string(default_value);

	type_config<uint16_t> some_config(default_value, DEFAULT_DESCRIPTION, key);

	ASSERT_EQ(expected_value, some_config.to_string());
}

TEST_F(type_config_test, vector_uint16_to_string)
{
	const std::string key = "int_vector";
	const std::vector<uint16_t>& default_value = INT_VECTOR_VALUE;
	const std::string expected_value = key + ": [5, 7, 27]";

	type_config<std::vector<uint16_t>> some_config(default_value,
	                                               DEFAULT_DESCRIPTION,
	                                               key);
	ASSERT_EQ(expected_value, some_config.to_string());
}

TEST_F(type_config_test, bool_get_default_true)
{
	const bool default_value = true;
	const std::string key = "my_key";

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

	ASSERT_EQ(default_value, some_config.get());
}

TEST_F(type_config_test, bool_get_default_false)
{
	const bool default_value = false;
	const std::string key = "my_key";

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

	ASSERT_EQ(default_value, some_config.get());
}

TEST_F(type_config_test, get_const_default)
{
	const std::string key = "my_key";

	const type_config<bool> some_config(DEFAULT_BOOL, DEFAULT_DESCRIPTION, key);

	ASSERT_EQ(DEFAULT_BOOL, some_config.get());
}

TEST_F(type_config_test, true_config_not_in_yaml_unmodified)
{
	const bool default_value = true;
	const std::string key = "my_key";

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(default_value, some_config.get());
}

TEST_F(type_config_test, false_config_not_in_yaml_unmodified)
{
	const bool default_value = false;
	const std::string key = "my_key";

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(default_value, some_config.get());
}

TEST_F(type_config_test, config_in_yaml_updated_true)
{
	const std::string key = "bool_true";
	const bool expected_value = true;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_in_yaml_updated_false)
{
	const std::string key = "bool_false";
	const bool expected_value = false;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value, DEFAULT_DESCRIPTION, key);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_with_subkey_in_yaml_updated_true)
{
	const std::string key = "bool_nested";
	const std::string subkey = "bool_true_nested";
	const bool expected_value = true;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value,
	                              DEFAULT_DESCRIPTION,
	                              key,
	                              subkey);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_with_subkey_in_yaml_updated_false)
{
	const std::string key = "bool_nested";
	const std::string subkey = "bool_false_nested";
	const bool expected_value = false;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value,
	                              DEFAULT_DESCRIPTION,
	                              key,
	                              subkey);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_with_subsubkey_in_yaml_updated_false)
{
	const std::string key = "bool_double_nested";
	const std::string subkey = "bool_double_nested_sub";
	const std::string subsubkey = "bool_true_double_nested";
	const bool expected_value = true;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value,
	                              DEFAULT_DESCRIPTION,
	                              key,
	                              subkey,
	                              subsubkey);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_with_subsubkey_in_yaml_updated_true)
{
	const std::string key = "bool_double_nested";
	const std::string subkey = "bool_double_nested_sub";
	const std::string subsubkey = "bool_false_double_nested";
	const bool expected_value = false;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value,
	                              DEFAULT_DESCRIPTION,
	                              key,
	                              subkey,
	                              subsubkey);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_string)
{
	const std::string key = "some_string";
	const std::string default_value = "xxxx";
	const std::string expected_value = "hello, world!";

	type_config<std::string> some_config(default_value,
	                                     DEFAULT_DESCRIPTION,
	                                     key);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, config_vector_uint16)
{
	const std::string key = "int_vector";
	const std::vector<uint16_t> default_value = { 14 };
	const std::vector<uint16_t>& expected_value = INT_VECTOR_VALUE;

	type_config<std::vector<uint16_t>> some_config(default_value,
	                                               DEFAULT_DESCRIPTION,
	                                               key);

 	yaml_configuration config_yaml({get_conf_file()});
 	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, builder_defaults)
{
	const std::string key = "int_12345";
	const int default_value = 10000;

	type_config<int>::mutable_ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
	   .get_mutable();

	yaml_configuration config_yaml({get_conf_file()});
	ASSERT_EQ(0, config_yaml.errors().size());

	some_config->init(config_yaml);
	some_config->post_init();

	ASSERT_EQ(INT_12345_VALUE, some_config->get());
	ASSERT_EQ(INT_12345_VALUE, some_config->configured());
	ASSERT_FALSE(some_config->hidden());
}

TEST_F(type_config_test, builder_hidden)
{
	const std::string key = "int_12345";
	const int default_value = 10000;

	type_config<int>::ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.hidden()
		.get();

	ASSERT_TRUE(some_config->hidden());
}

TEST_F(type_config_test, builder_min)
{
	const std::string key = "int_12345";
	const int default_value = 10000;
	const int MIN = INT_12345_VALUE + 10;

	type_config<int>::mutable_ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.min(MIN)
		.get_mutable();

	yaml_configuration config_yaml({get_conf_file()});
	ASSERT_EQ(0, config_yaml.errors().size());
	some_config->init(config_yaml);
	some_config->post_init();

	ASSERT_EQ(MIN, some_config->get());
	ASSERT_EQ(MIN, some_config->configured());
}

TEST_F(type_config_test, builder_max)
{
	const std::string key = "int_12345";
	const int default_value = 10000;
	const int MAX = INT_12345_VALUE - 10;

	type_config<int>::mutable_ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.max(MAX)
		.get_mutable();

	yaml_configuration config_yaml({get_conf_file()});
	ASSERT_EQ(0, config_yaml.errors().size());
	some_config->init(config_yaml);
	some_config->post_init();

	ASSERT_EQ(MAX, some_config->get());
	ASSERT_EQ(MAX, some_config->configured());
}

TEST_F(type_config_test, builder_post_init)
{
	const std::string key = "int_12345";
	const int default_value = 10000;
	const int FORCED = 99;

	type_config<int>::mutable_ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.post_init([](type_config<int>& config)
		{
			config.get() = FORCED;
		})
		.get_mutable();

	yaml_configuration config_yaml({get_conf_file()});
	ASSERT_EQ(0, config_yaml.errors().size());
	some_config->init(config_yaml);
	some_config->post_init();

	ASSERT_EQ(FORCED, some_config->get());
	ASSERT_EQ(INT_12345_VALUE, some_config->configured());
}



