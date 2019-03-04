#include <gtest.h>

#include "draios.pb.h"
#include "analyzer_file_stat.h"

class analyzer_file_stat_test : public testing::Test {};

TEST_F(analyzer_file_stat_test, top_files_map_below_limit) {
	analyzer_top_file_stat_map top_files;

	top_files["example.txt"].account_io(10000, 1000000);

	draiosproto::metrics metrics;

	top_files.emit(&metrics, 100);

	auto files = metrics.top_files();
	ASSERT_EQ(1, files.size());

	auto top_file = files[0];
	ASSERT_EQ("example.txt", top_file.name());
}

TEST_F(analyzer_file_stat_test, top_files_truncate) {
	analyzer_top_file_stat_map top_files;

	for (uint32_t i = 0; i < 100; ++i)
	{
		top_files["example" + std::to_string(i) + ".txt"].account_io(100, 1000);
	}

	top_files["example22.txt"].account_io(100, 1000);
	top_files["example3.txt"].account_io(200, 2000);
	top_files["example79.txt"].account_io(300, 3000);

	draiosproto::metrics metrics;

	top_files.emit(&metrics, 3);

	auto files = metrics.top_files();
	ASSERT_EQ(3, files.size());

	int found = 0;
	for (const auto& top_file : files)
	{
		found += (top_file.name() == "example22.txt");
		found += (top_file.name() == "example3.txt");
		found += (top_file.name() == "example79.txt");
	}

	ASSERT_EQ(3, found);
}

TEST_F(analyzer_file_stat_test, top_files_multi_criteria) {
	analyzer_top_file_stat_map top_files;

	for (uint32_t i = 0; i < 100; ++i)
	{
		top_files["example" + std::to_string(i) + ".txt"].account_io(100, 1000);
	}

	top_files["example41.txt"].account_io(100, 0);
	top_files["example63.txt"].account_io(200, 0);
	top_files["example2.txt"].account_io(300, 0);

	top_files["example83.txt"].account_io(0, 1000);
	top_files["example44.txt"].account_io(0, 2000);
	top_files["example7.txt"].account_io(0, 3000);

	draiosproto::metrics metrics;

	top_files.emit(&metrics, 3);

	auto files = metrics.top_files();
	ASSERT_EQ(6, files.size());

	int found = 0;
	for (const auto& top_file : files)
	{
		// top 3 by bytes
		found += (top_file.name() == "example41.txt");
		found += (top_file.name() == "example63.txt");
		found += (top_file.name() == "example2.txt");

		// top 3 by time
		found += (top_file.name() == "example83.txt");
		found += (top_file.name() == "example44.txt");
		found += (top_file.name() == "example7.txt");
	}

	ASSERT_EQ(6, found);
}
