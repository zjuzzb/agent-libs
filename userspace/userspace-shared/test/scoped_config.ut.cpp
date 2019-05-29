#include <gtest.h>
#include <scoped_config.h>

using namespace test_helpers;

TEST(scoped_config_test, key)
{
	const std::string key = "key1";
	type_config<int> some_config(10, "description", key);

	ASSERT_EQ(10, some_config.get());

	{
		scoped_config<int> config(key, 99);
		ASSERT_EQ(99, some_config.get());
	}

	ASSERT_EQ(10, some_config.get());
}

TEST(scoped_config_test, subkey)
{
	const std::string key = "key1";
	const std::string subkey = "subkey1";
	const std::string the_key = key + "." + subkey;

	type_config<int> some_config(10, "description", key, subkey);

	ASSERT_EQ(10, some_config.get());

	{
		scoped_config<int> config(the_key, 99);
		ASSERT_EQ(99, some_config.get());
	}

	ASSERT_EQ(10, some_config.get());
}

TEST(scoped_config_test, subsubkey)
{
	const std::string key = "key1";
	const std::string subkey = "subkey1";
	const std::string subsubkey = "subsubkey1";
	const std::string the_key = key + "." + subkey + "." + subsubkey;

	type_config<int> some_config(10, "description", key, subkey, subsubkey);

	ASSERT_EQ(10, some_config.get());

	{
		scoped_config<int> config(the_key, 99);
		ASSERT_EQ(99, some_config.get());
	}

	ASSERT_EQ(10, some_config.get());
}
