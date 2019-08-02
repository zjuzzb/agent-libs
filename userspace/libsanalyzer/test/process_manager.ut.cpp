#include "process_manager.h"
#include "analyzer_thread.h"
#include <gtest.h>

class test_helper
{
public:
        static void insert_app_check(thread_analyzer_info* ainfo, std::string value)
        {
                ainfo->m_app_checks_found.insert(value);
        }
};

TEST(process_manager_test, app_checks_always_send_config)
{
	std::string some_yaml = R"(
process:
  flush_filter:
    - include:
        all

app_checks_always_send: true
)";
	yaml_configuration config_yaml(some_yaml);
	ASSERT_EQ(0, config_yaml.errors().size());
	process_manager::c_always_send_app_checks.init(config_yaml);
	process_manager::c_process_filter.init(config_yaml);

	process_manager my_manager;

	sinsp_threadinfo tinfo;
	tinfo.m_ainfo = new thread_analyzer_info;
	bool matches = false;
	bool generic_match = false;
	matches = my_manager.get_flush_filter().matches(NULL, &tinfo, NULL, NULL, &generic_match, NULL);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, true);

	test_helper::insert_app_check(tinfo.m_ainfo, "some app check");
	matches = my_manager.get_flush_filter().matches(NULL, &tinfo, NULL, NULL, &generic_match, NULL);
	EXPECT_EQ(matches, true);
	EXPECT_EQ(generic_match, false);

	delete tinfo.m_ainfo;
}
