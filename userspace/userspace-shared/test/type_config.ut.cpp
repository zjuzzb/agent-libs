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

TEST_F(type_config_test, alternate_key_single_yaml)
{
	const std::string alternate_key = "some_string";
	const std::string default_value = "xxxx";
	const std::string expected_value = "hello, world!";

	type_config<std::string> some_config(default_value,
					     DEFAULT_DESCRIPTION,
					     "actual_key_does",
					     "not_exist");
	some_config.alternate_key(alternate_key);

	yaml_configuration config_yaml({ get_conf_file() });
	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, alternate_subkey_single_yaml)
{
	const std::string alternate_key = "bool_nested";
	const std::string alternate_subkey = "bool_true_nested";
	const bool expected_value = true;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value,
				      DEFAULT_DESCRIPTION,
				      "actual",
				      "key_does",
				      "not_exist");
	some_config.alternate_key(alternate_key, alternate_subkey);

	yaml_configuration config_yaml({ get_conf_file() });
	ASSERT_EQ(0, config_yaml.errors().size());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, alternate_subsubkey_single_yaml)
{
	const std::string alternate_key = "bool_double_nested";
	const std::string alternate_subkey = "bool_double_nested_sub";
	const std::string alternate_subsubkey = "bool_false_double_nested";
	const bool expected_value = false;
	const bool default_value = !expected_value;

	type_config<bool> some_config(default_value,
				      DEFAULT_DESCRIPTION,
				      "actual_key_does_not_exist");
	some_config.alternate_key(alternate_key, alternate_subkey, alternate_subsubkey);

	yaml_configuration config_yaml({ get_conf_file()});
	ASSERT_TRUE(config_yaml.errors().empty());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

TEST_F(type_config_test, key_takes_priority_in_shallower_yaml)
{
	test_helpers::scoped_temp_file primary_config;
	{
		std::ofstream out(primary_config.get_filename() .c_str());

		out << R"(
primary_key1: 22
)";
	}
	test_helpers::scoped_temp_file secondary_config;
	{
		std::ofstream out(secondary_config.get_filename() .c_str());

		out << R"(
primary_key1: 99
)";
	}

	const std::string primary_key = "primary_key1";
	const std::string alternate_key = "alternate_key1";
	const int default_value = 10;
	const int expected_value = 22;

	type_config<int> some_config(default_value,
				     DEFAULT_DESCRIPTION,
				     primary_key);
	some_config.alternate_key(alternate_key);

	yaml_configuration config_yaml({ primary_config.get_filename(),
					 secondary_config.get_filename() });
	ASSERT_TRUE(config_yaml.errors().empty());

	some_config.init(config_yaml);

	ASSERT_EQ(expected_value, some_config.get());
}

#define MULTI_YAML_TEST_EXPECT_22                                            \
type_config<int> some_config(10,                                               \
			     DEFAULT_DESCRIPTION,                              \
			     "primary_key1");                                  \
some_config.alternate_key("alternate_key1", "alternate_subkey1");              \
                                                                               \
yaml_configuration config_yaml({ primary_config.get_filename(),                \
	secondary_config.get_filename(),                                       \
	tertiary_config.get_filename()});                                      \
ASSERT_TRUE(config_yaml.errors() .empty());                                    \
                                                                               \
some_config.init(config_yaml);                                                 \
ASSERT_EQ(22, some_config.get() )

TEST_F(type_config_test, multiple_yaml_1)
{
	test_helpers::scoped_temp_file primary_config;
	{
		std::ofstream out(primary_config.get_filename() .c_str());

		out << R"(
unknown_key: 99
)";
	}
	test_helpers::scoped_temp_file secondary_config;
	{
		std::ofstream out(secondary_config.get_filename() .c_str());

		out << R"(
alternate_key1:
  alternate_subkey1: 22
)";
	}
	test_helpers::scoped_temp_file tertiary_config;
	{
		std::ofstream out(tertiary_config.get_filename().c_str());

		out << R"(
primary_key1: 77
)";
	}

	MULTI_YAML_TEST_EXPECT_22;
}

TEST_F(type_config_test, multiple_yaml_2)
{
	test_helpers::scoped_temp_file primary_config;
	{
		std::ofstream out(primary_config.get_filename() .c_str());

		out << R"(
alternate_key1:
  alternate_subkey2: 23
)";
	}
	test_helpers::scoped_temp_file secondary_config;
	{
		std::ofstream out(secondary_config.get_filename() .c_str());

		out << R"(
alternate_key1:
  alternate_subkey1: 22
)";
	}
	test_helpers::scoped_temp_file tertiary_config;
	{
		std::ofstream out(tertiary_config.get_filename().c_str());

		out << R"(
primary_key1: 77
)";
	}

	MULTI_YAML_TEST_EXPECT_22;
}

TEST_F(type_config_test, multiple_yaml_3)
{
	test_helpers::scoped_temp_file primary_config;
	{
		std::ofstream out(primary_config.get_filename().c_str());

		out << R"(
primary_key1: 22
)";
	}
	test_helpers::scoped_temp_file secondary_config;
	{
		std::ofstream out(secondary_config.get_filename().c_str());

		out << R"(
alternate_key1:
  alternate_subkey1: 88
)";
	}
	test_helpers::scoped_temp_file tertiary_config;
	{
		std::ofstream out(tertiary_config.get_filename().c_str());

		out << R"(
primary_key1: 77
)";
	}

	MULTI_YAML_TEST_EXPECT_22;
}

TEST_F(type_config_test, multiple_yaml_4)
{
	test_helpers::scoped_temp_file primary_config;
	{
		std::ofstream out(primary_config.get_filename().c_str());

		out << R"(
alternate_key1:
  alternate_subkey1: 22
)";
	}
	test_helpers::scoped_temp_file secondary_config;
	{
		std::ofstream out(secondary_config.get_filename().c_str());

		out << R"(
alternate_key1:
  alternate_subkey1: 44
)";
	}
	test_helpers::scoped_temp_file tertiary_config;
	{
		std::ofstream out(tertiary_config.get_filename().c_str());

		out << R"(
primary_key1: 77
)";
	}

	MULTI_YAML_TEST_EXPECT_22;
}

TEST_F(type_config_test, config_has_both_primary_and_alternate_key)
{
	test_helpers::scoped_temp_file primary_config;
	{
		std::ofstream out(primary_config.get_filename() .c_str());

		out << R"(
primary_key1: 99
alternate_key1: 22
)";
	}
	test_helpers::scoped_temp_file secondary_config;
	{
		std::ofstream out(secondary_config.get_filename() .c_str());

		out << R"(
primary_key1: 99
)";
	}

	const std::string primary_key = "primary_key1";
	const std::string alternate_key = "alternate_key1";
	const int default_value = 10;

	type_config<int> some_config(default_value,
				     DEFAULT_DESCRIPTION,
				     primary_key);
	some_config.alternate_key(alternate_key);

	yaml_configuration config_yaml({ primary_config.get_filename(),
					 secondary_config.get_filename() });
	ASSERT_EQ(0, config_yaml.errors().size());

	EXPECT_THROW(some_config.init(config_yaml), yaml_configuration_exception);
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

TEST_F(type_config_test, builder_min_over)
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

TEST_F(type_config_test, builder_min_under)
{
	const std::string key = "int_12345";
	const int default_value = 10000;
	const int MIN = INT_12345_VALUE - 10;

	type_config<int>::mutable_ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.min(MIN)
		.get_mutable();

	yaml_configuration config_yaml({get_conf_file()});
	ASSERT_EQ(0, config_yaml.errors().size());
	some_config->init(config_yaml);
	some_config->post_init();

	ASSERT_EQ(INT_12345_VALUE, some_config->get());
	ASSERT_EQ(INT_12345_VALUE, some_config->configured());
}

TEST_F(type_config_test, builder_max_under)
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

TEST_F(type_config_test, builder_max_over)
{
	const std::string key = "int_12345";
	const int default_value = 10000;
	const int MAX = INT_12345_VALUE + 10;

	type_config<int>::mutable_ptr some_config =
	   type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.max(MAX)
		.get_mutable();

	yaml_configuration config_yaml({get_conf_file()});
	ASSERT_EQ(0, config_yaml.errors().size());
	some_config->init(config_yaml);
	some_config->post_init();

	ASSERT_EQ(INT_12345_VALUE, some_config->get());
	ASSERT_EQ(INT_12345_VALUE, some_config->configured());
}

TEST_F(type_config_test, mutable_only_in_internal_build)
{
	const std::string key = "int_12345";
	const int default_value = 10000;

	type_config<int>::mutable_ptr some_config =
	    type_config_builder<int>(default_value, DEFAULT_DESCRIPTION, key)
		.mutable_only_in_internal_build()
		.get_mutable();

	yaml_configuration config_yaml({ get_conf_file() });
	ASSERT_EQ(0, config_yaml.errors().size());
	some_config->init(config_yaml);
	some_config->post_init();

	// Since this ut is part of an internal build, we can only check that
	// the value was written.
	ASSERT_EQ(INT_12345_VALUE, some_config->get());
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

/**
 * Ensure that to_json() returns a JSON-based representation of the given
 * object.
 */
TEST_F(type_config_test, to_json)
{
	const type_config<bool> c(false, "some description", "some_test_key");
	const std::string json = c.to_json();

	const std::string expected_json = R"EOF({
   "some_test_key" : {
      "description" : "some description",
      "value" : "false"
   }
}
)EOF";

      	ASSERT_EQ(expected_json, json);
}

/**
 * Ensure that string_to_value() will update a config value of type int when
 * the given string is an int.
 */
TEST_F(type_config_test, string_to_value_int_valid)
{
	type_config<int> c(42, "some description", "some_test_key");
	
	ASSERT_TRUE(c.string_to_value("17"));
	ASSERT_EQ(17, c.get());
}

/**
 * Ensure that string_to_value() will not update a config value of type int when
 * the given string is not an int.
 */
TEST_F(type_config_test, string_to_value_int_invalid)
{
	type_config<int> c(42, "some description", "some_test_key");
	
	ASSERT_FALSE(c.string_to_value("true"));
	ASSERT_EQ(42, c.get());
}

/**
 * Ensure that string_to_value() will update a config value of type string
 */
TEST_F(type_config_test, string_to_value_string)
{
	type_config<std::string> c("original value", "some description", "some_test_key");
	
	ASSERT_TRUE(c.string_to_value("new value"));
	ASSERT_EQ("new value", c.get());
}

/**
 * Ensure that string_to_value() will update a config value of type bool when
 * the given string is a bool.
 */
TEST_F(type_config_test, string_to_value_bool_valid)
{
	type_config<bool> c(true, "some description", "some_test_key");
	
	ASSERT_TRUE(c.string_to_value("false"));
	ASSERT_FALSE(c.get());
}

/**
 * Ensure that string_to_value() will update a config value of type bool when
 * the given string is a bool (mixed case).
 */
TEST_F(type_config_test, string_to_value_bool_valid_mixed_case)
{
	type_config<bool> c(true, "some description", "some_test_key");
	
	ASSERT_TRUE(c.string_to_value("fAlSe"));
	ASSERT_FALSE(c.get());
}

/**
 * Ensure that string_to_value() will not update a config value of type bool when
 * the given string is not a bool.
 */
TEST_F(type_config_test, string_to_value_bool_invalid)
{
	type_config<bool> c(true, "some description", "some_test_key");
	
	ASSERT_FALSE(c.string_to_value("0"));
	ASSERT_TRUE(c.get());
}

/**
 * string_to_value() doesn't currently support config of type vector.
 * Ensure that it returns false.
 */
TEST_F(type_config_test, string_to_value_vector_invalid)
{
	type_config<std::vector<int>> c({1, 2, 3}, "some description", "some_test_key");
	
	ASSERT_FALSE(c.string_to_value("[4, 5, 6]"));
	ASSERT_EQ((std::vector<int>{1, 2, 3}), c.get());
}

/**
 * Ensure that if a client calls from_json() with invalid JSON, the method
 * throws a configuration_unit::exception.
 */
TEST_F(type_config_test, from_json_invalid_json)
{
	type_config<int> c(1, "some description", "some_test_key");

	ASSERT_THROW(c.from_json("this is not json"),
	             configuration_unit::exception);
}

/**
 * Ensure that if a client calls from_json() with valid JSON, but omits the
 * "value" element, the method throws a configuration_unit::exception.
 */
TEST_F(type_config_test, from_json_valid_json_no_value)
{
	type_config<int> c(1, "some description", "some_test_key");

	ASSERT_THROW(c.from_json(R"EOF({ "name": "bob" })EOF"),
	             configuration_unit::exception);
}

/**
 * Ensure that if a client calls from_json() with valid JSON, with a "value"
 * element, but the type of the value doesn't match the type of the config,
 * the method throws a configuration_unit::exception.
 */
TEST_F(type_config_test, from_json_valid_json_value_wrong_type)
{
	type_config<int> c(1, "some description", "some_test_key");

	ASSERT_THROW(c.from_json(R"EOF({ "value": "this is not an int" })EOF"),
	             configuration_unit::exception);
}

/**
 * Ensure that if a client calls from_json() with valid JSON, with a "value"
 * element, and the type of the value matches the type of the config, the
 * method updates the config's value.
 */
TEST_F(type_config_test, from_json_valid_json_value_correct_type_int)
{
	type_config<int> c(1, "some description", "some_test_key");

	ASSERT_NO_THROW(c.from_json(R"EOF({ "value": "27" })EOF"));
	ASSERT_EQ(27, c.get());
}

/**
 * Ensure that if a client calls from_json() with valid JSON, with a "value"
 * element, and the type of the value matches the type of the config, the
 * method updates the config's value.
 */
TEST_F(type_config_test, from_json_valid_json_value_correct_type_bool)
{
	type_config<bool> c(true, "some description", "some_test_key");

	ASSERT_NO_THROW(c.from_json(R"EOF({ "value": "false" })EOF"));
	ASSERT_FALSE(c.get());
}

/**
 * Ensure that if a client calls from_json() with valid JSON, with a "value"
 * element, and the type of the value matches the type of the config, the
 * method updates the config's value.
 */
TEST_F(type_config_test, from_json_valid_json_value_correct_type_string)
{
	type_config<std::string> c("start value", "some description", "some_test_key");

	ASSERT_NO_THROW(c.from_json(R"EOF({ "value": "new value" })EOF"));
	ASSERT_EQ("new value", c.get());
}

