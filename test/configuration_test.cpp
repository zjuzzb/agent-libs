#include <fstream>
#include <streambuf>

#include <gtest.h>
#include <Poco/File.h>

#include <configuration.h>

using namespace std;

class configuration_test : public testing::Test
{
protected:

	virtual void SetUp()
	{
		// Create a temporary directory where all the files
		// related to this test will reside.
		char pat[28];
		strcpy(pat, "/tmp/auto_config_testXXXXXX");
		ASSERT_TRUE(mkdtemp(pat) != NULL);
		m_auto_config_dir = pat;

//		fprintf(stdout, "Set auto config root to %s\n", m_auto_config_dir.c_str());

		m_config.init(NULL);
		m_config.set_auto_config_directory(m_auto_config_dir);

		// The (global) logger only needs to be set up once
		if(!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, (Message::Priority) -1);

			g_log = std::unique_ptr<dragent_logger>(new dragent_logger(&loggerc, &loggerc));
		}
	}

	virtual void TearDown()
	{
		Poco::File tmpdir(m_auto_config_dir);
		tmpdir.remove(true);
	}

	dragent_configuration m_config;
	string m_auto_config_dir;
};

static bool verify_file_contents(const char *path, const char *contents)
{
	std::ifstream str(path);
	std::string actual((std::istreambuf_iterator<char>(str)),
			   std::istreambuf_iterator<char>());

	char *p = strstr((char *) actual.c_str(), contents);

	return (p != NULL && *(p+strlen(contents)) == '\0');
}

TEST_F(configuration_test, dragent_auto_config)
{
	string errstr;

	// Load a configuration for a file type that is not supported,
	// verify failure.
	ASSERT_EQ(m_config.save_auto_config("not-a-file", "", errstr), -1);
	ASSERT_STREQ(errstr.c_str(), "Auto config filename not-a-file is not a supported auto configuration file type");

        // Load a configuration with these errors, verify failure:
        //  - Not yaml
        //  - yaml that tries to override a forbidden key
	ASSERT_EQ(m_config.save_auto_config("dragent.auto.yaml", "not yaml", errstr), -1);
	ASSERT_STREQ(errstr.c_str(), "New auto config is not valid, skipping it");

	ASSERT_EQ(m_config.save_auto_config("dragent.auto.yaml", "auto_config: false", errstr), -1);
	ASSERT_STREQ(errstr.c_str(), "Overriding key=auto_config on autoconfig is forbidden");

	// Load a configuration with no errors, verify success.
	ASSERT_EQ(m_config.save_auto_config("dragent.auto.yaml", "my_key: value1", errstr), 1);
	ASSERT_TRUE(verify_file_contents(Path(m_auto_config_dir).append("dragent.auto.yaml").toString().c_str(), "my_key: value1"));

	// Reload a second configuration with errors, verify failure
	// and that the first file remains loaded.
	ASSERT_EQ(m_config.save_auto_config("dragent.auto.yaml", "also not yaml", errstr), -1);
	ASSERT_TRUE(verify_file_contents(Path(m_auto_config_dir).append("dragent.auto.yaml").toString().c_str(), "my_key: value1"));

	// Reload a second configuration with no errors, verify
	// success and that the first file is overwritten.
	ASSERT_EQ(m_config.save_auto_config("dragent.auto.yaml", "my_key: value3", errstr), 1);
	ASSERT_TRUE(verify_file_contents(Path(m_auto_config_dir).append("dragent.auto.yaml").toString().c_str(), "my_key: value3"));

	// Reload the configuration a second time, verify that nothing is updated
	ASSERT_EQ(m_config.save_auto_config("dragent.auto.yaml", "my_key: value3", errstr), 0);
}
