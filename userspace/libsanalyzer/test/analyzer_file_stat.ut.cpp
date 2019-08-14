#include <gtest.h>

#include "draios.pb.h"
#include "analyzer_file_stat.h"

class analyzer_file_stat_test : public testing::Test {};

TEST_F(analyzer_file_stat_test, top_files_map_below_limit) {
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	analyzer_top_file_stat_map top_files;

	top_files["example.txt"].account_io(10000, 1000000, read);

	draiosproto::metrics metrics;

	top_files.emit(&metrics, 100);

	auto files = metrics.top_files();
	ASSERT_EQ(1, files.size());

	auto top_file = files[0];
	ASSERT_EQ("example.txt", top_file.name());
}

TEST_F(analyzer_file_stat_test, top_files_truncate) {
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	analyzer_top_file_stat_map top_files;

	for (uint32_t i = 0; i < 100; ++i)
	{
		top_files["example" + std::to_string(i) + ".txt"].account_io(100, 1000, read);
	}

	top_files["example22.txt"].account_io(100, 1000, read);
	top_files["example3.txt"].account_io(200, 2000, read);
	top_files["example79.txt"].account_io(300, 3000, read);

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
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	analyzer_top_file_stat_map top_files;

	for (uint32_t i = 0; i < 100; ++i)
	{
		top_files["example" + std::to_string(i) + ".txt"].account_io(100, 1000, read);
	}

	top_files["example41.txt"].account_io(100, 0, read);
	top_files["example63.txt"].account_io(200, 0, read);
	top_files["example2.txt"].account_io(300, 0, read);

	top_files["example83.txt"].account_io(0, 1000, read);
	top_files["example44.txt"].account_io(0, 2000, read);
	top_files["example7.txt"].account_io(0, 3000, read);

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

TEST_F(analyzer_file_stat_test, file_stat_bytes_in)
{
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	analyzer_file_stat file_stat;

	file_stat.account_io(1, 2, read);
	file_stat.account_io(1, 2, read);

	ASSERT_EQ(2, file_stat.bytes());
	ASSERT_EQ(2, file_stat.bytes_in());
	ASSERT_EQ(0, file_stat.bytes_out());
}

TEST_F(analyzer_file_stat_test, file_stat_bytes_out)
{
	const analyzer_file_stat::io_direction write = analyzer_file_stat::io_direction::WRITE;
	analyzer_file_stat file_stat;


	file_stat.account_io(1, 2, write);
	file_stat.account_io(1, 2, write);

	ASSERT_EQ(2, file_stat.bytes());
	ASSERT_EQ(0, file_stat.bytes_in());
	ASSERT_EQ(2, file_stat.bytes_out());
}

TEST_F(analyzer_file_stat_test, file_stat_bytes_in_out)
{
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	const analyzer_file_stat::io_direction write = analyzer_file_stat::io_direction::WRITE;
	analyzer_file_stat file_stat;

	file_stat.account_io(1, 2, read);
	file_stat.account_io(1, 2, write);

	ASSERT_EQ(2, file_stat.bytes());
	ASSERT_EQ(1, file_stat.bytes_in());
	ASSERT_EQ(1, file_stat.bytes_out());
}

TEST_F(analyzer_file_stat_test, bytes_in_plus_equals)
{
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	analyzer_file_stat lhs;
	analyzer_file_stat rhs;

	lhs.account_io(10, 1, read);
	rhs.account_io(7, 1, read);

	lhs += rhs;

	ASSERT_EQ(17, lhs.bytes_in());
}

TEST_F(analyzer_file_stat_test, bytes_out_plus_equals)
{
	const analyzer_file_stat::io_direction write = analyzer_file_stat::io_direction::WRITE;
	analyzer_file_stat lhs;
	analyzer_file_stat rhs;


	lhs.account_io(5,  1, write);
	rhs.account_io(14, 1, write);

	lhs += rhs;

	ASSERT_EQ(19, lhs.bytes_out());
}

TEST_F(analyzer_file_stat_test, to_protobuf_bytes_in)
{
	const analyzer_file_stat::io_direction read = analyzer_file_stat::io_direction::READ;
	analyzer_file_stat file_stat;
	draiosproto::file_stat protobuf;

	file_stat.account_io(10, 1, read);

	file_stat.to_protobuf(&protobuf);

	ASSERT_EQ(10, protobuf.bytes_in());
}

TEST_F(analyzer_file_stat_test, to_protobuf_bytes_out)
{
	const analyzer_file_stat::io_direction write = analyzer_file_stat::io_direction::WRITE;
	analyzer_file_stat file_stat;
	draiosproto::file_stat protobuf;

	file_stat.account_io(5, 1, write);

	file_stat.to_protobuf(&protobuf);

	ASSERT_EQ(5, protobuf.bytes_out());
}
