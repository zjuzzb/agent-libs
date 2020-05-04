#include <gtest.h>
#include "com_sysdigcloud_sdjagent_CLibrary.h"
#include "jni_utils.h"

class test_fixture : public ::testing::Test
{
protected:

private:
	virtual void SetUp()
	{
		// create some hsperfdata files
		mkdir("/tmp/hsperfdata_test", S_IRWXU);
		mkdir("/tmp/hsperfdata_test2", S_IRWXU);
		mkdir("/tmp/hsperfdata_test/3", S_IRWXU);
		mkdir("/tmp/hsperfdata_test/4", S_IRWXU);
		mkdir("/tmp/hsperfdata_test2/5", S_IRWXU);
		mkdir("/tmp/hsperfdata_test2/6", S_IRWXU);
	}

	virtual void TearDown()
	{
		rmdir("/tmp/hsperfdata_test/3");
		rmdir("/tmp/hsperfdata_test/4");
		rmdir("/tmp/hsperfdata_test2/5");
		rmdir("/tmp/hsperfdata_test2/6");
		rmdir("/tmp/hsperfdata_test");
		rmdir("/tmp/hsperfdata_test2");
	}

};

TEST_F(test_fixture, find_hsperfdata_by_pid_test)
{
	EXPECT_EQ(hsperfdata_utils::find_hsperfdata_by_pid(3), "/tmp/hsperfdata_test/3");
	EXPECT_EQ(hsperfdata_utils::find_hsperfdata_by_pid(4), "/tmp/hsperfdata_test/4");
	EXPECT_EQ(hsperfdata_utils::find_hsperfdata_by_pid(5), "/tmp/hsperfdata_test2/5");
	EXPECT_EQ(hsperfdata_utils::find_hsperfdata_by_pid(6), "/tmp/hsperfdata_test2/6");
	EXPECT_EQ(hsperfdata_utils::find_hsperfdata_by_pid(88888), "");
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
