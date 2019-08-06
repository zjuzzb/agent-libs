#include <gtest.h>
#include <type_config.h>
#include <scoped_configuration.h>

using namespace test_helpers;

TEST(scoped_configuration_test, basic)
{
	const std::string key = "key1";
	type_config<int> config1(1, "description", "key1", "subkey1");
	type_config<int> config2(2, "description", "key1", "subkey2");
	type_config<int> config3(3, "description", "key2");
	type_config<int> config4(4, "description", "key3", "subkey1", "subsubkey1");
	type_config<int> config5(5, "description", "key4");

	ASSERT_EQ(1, config1.get());
	ASSERT_EQ(2, config2.get());
	ASSERT_EQ(3, config3.get());
	ASSERT_EQ(4, config4.get());
	ASSERT_EQ(5, config5.get());

	{	scoped_configuration config(R"(
key1:
  subkey1: 101
  subkey2: 102
key2: 103
key3:
  subkey1:
    subsubkey1: 104)");

		ASSERT_EQ(101, config1.get());
		ASSERT_EQ(102, config2.get());
		ASSERT_EQ(103, config3.get());
		ASSERT_EQ(104, config4.get());
		ASSERT_EQ(5, config5.get());
	}

	ASSERT_EQ(1, config1.get());
	ASSERT_EQ(2, config2.get());
	ASSERT_EQ(3, config3.get());
	ASSERT_EQ(4, config4.get());
	ASSERT_EQ(5, config5.get());
}

TEST(scoped_configuration_test, default_constructor)
{
	type_config<int> config1(1, "description", "key1", "subkey1");

	{
		scoped_configuration config;

		config1.set(42);
		ASSERT_EQ(42, config1.get());
	}

	ASSERT_EQ(1, config1.get());
}
