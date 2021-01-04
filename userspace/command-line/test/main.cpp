#include <gtest.h>

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	const int exit_status = RUN_ALL_TESTS();

	return exit_status;
}

