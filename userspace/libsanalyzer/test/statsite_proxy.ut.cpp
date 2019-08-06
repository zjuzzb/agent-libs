/**
 * @file
 *
 * Unit tests for statsite_proxy.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#include "statsite_proxy.h"
#include "scoped_fmemopen.h"
#include <string>
#include <gtest.h>

using test_helpers::scoped_fmemopen;

namespace
{
	const std::string STATSITE_OUTPUT = 
R"EOF(counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam5|86.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam8|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam10|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam8|86.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam4|86.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam9|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam5|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam4|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam3|85.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam7|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam7|86.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam6|86.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam1|85.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam9|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam6|86.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam2|85.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam10|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam1|85.000000|1432288305
counts.3ce9120d8307$totam.sunt.consequatur.numquam.aperiam3|86.000000|1432288305
counts.totam.sunt.consequatur.numquam.aperiam2|85.000000|1432288305)EOF";

	const std::string STATSITE_OUTPUT_LONG = ""
		"counts.totam.sunt.consequatur.numquam.aperiamRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
		"RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRREEEEEEEEEEEE"
		"EEEEEEEEEEEEEEEEEALLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLYY"
		"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYLLLLLLLLLLLLL"
		"LLLLLLLLLOOOOOOOOOOOOOOOOOOOOOOOONNNNNNNNNNNNNNNNNNNNGGGGGGGGG"
		"GGGG|85.000000|1432288305";

/**
 * Send the given stats to statsite_proxy and let it validate it for
 * correctness.  If it's valid, statsite_proxy will write it to the appropriate
 * FILE*, which we can later inspect.
 *
 * @param[in] stats    a potential statsd metric (valid or invalid).
 * @param[in] expected What the client expects statsite_proxy to write to 
 *                     the FILE*.
 */
void do_statsite_proxy_validation(const std::string& stats,
		                  const std::string& expected)
{
	scoped_fmemopen in(512, "r+");
	scoped_fmemopen out(2, "r+");

	ASSERT_NO_THROW({
		const bool check_format = true;
		statsite_proxy proxy(std::make_pair(in.get_file(), out.get_file()),
		                     check_format);

		proxy.send_metric(stats.c_str(), stats.size());
	});

	ASSERT_EQ(expected, in.get_buffer_content());
}

} // end namespace

TEST(statsite_proxy_test, parser)
{
	scoped_fmemopen output_file(STATSITE_OUTPUT.size(), "r", STATSITE_OUTPUT);
	scoped_fmemopen input_file(2, "w");

	const bool check_format = false;
	statsite_proxy proxy(std::make_pair(input_file.get_file(),
	                                    output_file.get_file()),
	                     check_format);

	const auto ret = proxy.read_metrics();
	EXPECT_EQ(2U, ret.size());
	EXPECT_EQ(10U, std::get<0>(ret.at("")).size());
	EXPECT_EQ(10U, std::get<0>(ret.at("3ce9120d8307")).size());

	std::set<std::string> reference_set;
	for(unsigned j = 1; j < 11; ++j)
	{
		reference_set.insert(std::string("totam.sunt.consequatur.numquam.aperiam") + std::to_string(j));
	}

	for(const auto& item : ret)
	{
		std::set<std::string> found_set;

		for(const auto& m : std::get<0>(item.second))
		{
			found_set.insert(m.name());
		}
		for(const auto& ref : reference_set)
		{
			EXPECT_TRUE(found_set.find(ref) != found_set.end()) << ref << " not found for " << item.first;
		}
	}
}

// same as the parser test, but we have a line in there longer than the buffer size to ensure it gets nuked from space properly
TEST(statsite_proxy_test, parser_long)
{
	scoped_fmemopen output_file(STATSITE_OUTPUT_LONG.size(), "r", STATSITE_OUTPUT_LONG);
	scoped_fmemopen input_file(2, "w");

	const bool check_format = false;
	statsite_proxy proxy(std::make_pair(input_file.get_file(),
	                                    output_file.get_file()),
	                     check_format);

	auto ret = proxy.read_metrics();
	ASSERT_EQ(1U, ret.size());
	EXPECT_EQ(1U, std::get<0>(ret.at("")).size());

	std::set<std::string> reference_set;

	// must match the string in the above file. Chosen to be longer than the
	// default max length above which we have to reallocate a larger buffer and
	// log a comment
	reference_set.insert("totam.sunt.consequatur.numquam.aperiamRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRREEEEEEEEEEEEEEEEEEEEEEEEEEEEEALLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYLLLLLLLLLLLLLLLLLLLLLLOOOOOOOOOOOOOOOOOOOOOOOONNNNNNNNNNNNNNNNNNNNGGGGGGGGGGGGG");
	for(const auto& item : ret)
	{
		std::set<std::string> found_set;
		for(const auto& m : std::get<0>(item.second))
		{
			found_set.insert(m.name());
		}
		for(const auto& ref : reference_set)
		{
			EXPECT_TRUE(found_set.find(ref) != found_set.end()) << ref << " not found for " << item.first;
		}
	}
}

/**
 * Ensure that writing a single metric without a trailing newline is validated
 */
TEST(statsite_proxy_test, single_metric_no_newline_validated)
{
	const std::string valid_metric = "a:b|c";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing a single metric with a trailing newline is validated.
 */
TEST(statsite_proxy_test, single_metric_no_newline_extra_pipe_validated)
{
	const std::string valid_metric = "a:b|c\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing a single metric with an extra pipe and without a
 * trailing newline is validated.
 */
TEST(statsite_proxy_test, single_metric_extra_pipe_no_newline)
{
	const std::string valid_metric = "a:b|c|d";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing a single metric with an extra pipe and with a
 * trailing newline is validated.
 */
TEST(statsite_proxy_test, single_metric_extra_pipe_newline)
{
	const std::string valid_metric = "a:b|c|d\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics without a trailing newline is validated
 */
TEST(statsite_proxy_test, multiple_metrics_no_newline_validated)
{
	const std::string valid_metric = "a:b|c\nd:e|f";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with a trailing newline is validated
 */
TEST(statsite_proxy_test, multiple_metrics_newline_validated)
{
	const std::string valid_metric = "a:b|c\nd:e|f\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with extra pipes, without a trailing
 * newline is validated
 */
TEST(statsite_proxy_test, multiple_metrics_extra_pipe_no_newline_validated)
{
	const std::string valid_metric = "a:b|c|d\ne:f|g|h";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with extra pipes, with a trailing
 * newline is validated
 */
TEST(statsite_proxy_test, multiple_metrics_extra_pipe_newline_validated)
{
	const std::string valid_metric = "a:b|c|d\ne:f|g|h\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing a single metric with multiple characters and no newline
 * is validated.
 */
TEST(statsite_proxy_test, single_metric_multiple_characters_no_newline)
{
	const std::string valid_metric = "abc:defg|hijklmn";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing a single metric with multiple characters and a trailing
 * newline is validated.
 */
TEST(statsite_proxy_test, single_metric_multiple_characters_newline)
{
	const std::string valid_metric = "abc:defg|hijklmn\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with multiple characters and no
 * trailing newline is validated.
 */
TEST(statsite_proxy_test, multiple_metrics_multiple_characters_no_newline)
{
	const std::string valid_metric = "abc:defg|hijklmn\nop:qr|st";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with multiple characters and a
 * trailing newline is validated.
 */
TEST(statsite_proxy_test, multiple_metrics_multiple_characters_newline)
{
	const std::string valid_metric = "abc:defg|hijklmn\nop:qr|st\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with multiple characters, multiple
 * pipes, and no trailing newline is validated.
 */
TEST(statsite_proxy_test, multiple_metrics_multiple_characters_extra_pipe_no_newline)
{
	const std::string valid_metric = "abc:defg|hijklmn|zzz\nop:qr|st|xxx";
	const std::string expected = valid_metric + "\n";

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that writing multiple metrics with multiple characters, multiple
 * pipes, and with a trailing newline is validated.
 */
TEST(statsite_proxy_test, multiple_metrics_multiple_characters_extra_pipe_newline)
{
	const std::string valid_metric = "abc:defg|hijklmn|zzz\nop:qr|st|xxx\n";
	const std::string expected = valid_metric;

	do_statsite_proxy_validation(valid_metric, expected);
}

/**
 * Ensure that if a colon is missing, the metric is not validated.
 */
TEST(statsite_proxy_test, single_metric_missing_colon_invalid)
{
	const std::string invalid_metric = "ab|c";
	const std::string expected = "";

	do_statsite_proxy_validation(invalid_metric, expected);
}

/**
 * Ensure that if a colon is missing, the entire buffer is not validated.
 */
TEST(statsite_proxy_test, multiple_metrics_missing_colon_invalid)
{
	const std::string invalid_metric = "ab|c\na:b|c";
	const std::string expected = "";

	do_statsite_proxy_validation(invalid_metric, expected);
}

/**
 * Ensure that if a pipe is missing, the metric is not validated.
 */
TEST(statsite_proxy_test, single_metric_missing_pipe_invalid)
{
	const std::string invalid_metric = "a:bc";
	const std::string expected = "";

	do_statsite_proxy_validation(invalid_metric, expected);
}

/**
 * Ensure that if a pipe is missing, the entire buffer is not validated.
 */
TEST(statsite_proxy_test, multiple_metrics_missing_pipe_invalid)
{
	const std::string invalid_metric = "a:bc\na:b|c";
	const std::string expected = "";

	do_statsite_proxy_validation(invalid_metric, expected);
}

/**
 * Ensure that a metric containing only pipes is invalid.
 */
TEST(statsite_proxy_test, only_pipes_invalid)
{
	const std::string invalid_metric = "a|b|c";
	const std::string expected = "";

	do_statsite_proxy_validation(invalid_metric, expected);
}

/**
 * Ensure that a metric containing only colons is invalid.
 */
TEST(statsite_proxy_test, only_colons_invalid)
{
	const std::string invalid_metric = "a:b:c";
	const std::string expected = "";

	do_statsite_proxy_validation(invalid_metric, expected);
}

/**
 * Ensure that having extra colons in various invalid places is not
 * validated.
 */
TEST(statsite_proxy_test, random_extra_colons_invalid)
{
	const std::string expected = "";

	do_statsite_proxy_validation(":a:b|c\na:b|c", expected);
	do_statsite_proxy_validation("a::b|c\na:b|c", expected);
	do_statsite_proxy_validation("a:b|:c\na:b|c", expected);
	do_statsite_proxy_validation("a:b|c\n:a:b|c", expected);
	do_statsite_proxy_validation("a:b|c\na:b:|c", expected);
	do_statsite_proxy_validation("a:b|c\na:b:|c:", expected);
}

/**
 * Ensure that having extra pipes in various invalid places is not
 * validated.
 */
TEST(statsite_proxy_test, random_extra_pipes_invalid)
{
	const std::string expected = "";

	do_statsite_proxy_validation("|a:b|c\na:b|c", expected);
	do_statsite_proxy_validation("a|:b|c\na:b|c", expected);
	do_statsite_proxy_validation("a:b||c\na:b|c", expected);
	do_statsite_proxy_validation("a:b|c\n|a:b|c", expected);
	do_statsite_proxy_validation("a:b|c\na:b||c", expected);
	do_statsite_proxy_validation("a:b|c\na:b:|c|", expected);
}

/**
 * Ensure that having extra newlines in various invalid places is not
 * validated.
 */
TEST(statsite_proxy_test, random_extra_newlines_invalid)
{
	const std::string expected = "";

	do_statsite_proxy_validation("\na:b|c\na:b|c", expected);
	do_statsite_proxy_validation("a:\nb|c\na:b|c", expected);
	do_statsite_proxy_validation("a:b|\nc\na:b|c", expected);
	do_statsite_proxy_validation("a:b|c\n\na:b|c", expected);
	do_statsite_proxy_validation("a:b|c\na:b\n|c", expected);
}

TEST(statsite_proxy_test, read_metrics_filter_wildcard)
{
	scoped_fmemopen output_file(STATSITE_OUTPUT.size(), "r", STATSITE_OUTPUT);
	scoped_fmemopen input_file(2, "w");

	const bool check_format = false;
	statsite_proxy proxy(std::make_pair(input_file.get_file(),
	                                    output_file.get_file()),
	                     check_format);

	filter_vec_t f = {
		{"totam.sunt.consequatur.numquam.aperiam5", true},
		{"totam.*", false}
	};
	metric_limits::sptr_t ml(new metric_limits(f));
	auto ret = proxy.read_metrics(ml);
	EXPECT_EQ(2U, ret.size());
	EXPECT_EQ(1U, std::get<0>(ret.at("")).size());
	EXPECT_EQ(1U, std::get<0>(ret.at("3ce9120d8307")).size());
}

TEST(statsite_proxy_test, read_metrics_filter_questionmark)
{
	scoped_fmemopen output_file(STATSITE_OUTPUT.size(), "r", STATSITE_OUTPUT);
	scoped_fmemopen input_file(2, "w");

	const bool check_format = false;
	statsite_proxy proxy(std::make_pair(input_file.get_file(),
	                                    output_file.get_file()),
	                     check_format);

	filter_vec_t f = {
		{"*1?", true},
		{"totam.sunt.consequatur.numquam.aperiam7", true},
		{"*", false}
	};
	metric_limits::sptr_t ml(new metric_limits(f));
	auto ret = proxy.read_metrics(ml);
	EXPECT_EQ(2U, ret.size());
	EXPECT_EQ(2U, std::get<0>(ret.at("")).size());
	EXPECT_EQ(2U, std::get<0>(ret.at("3ce9120d8307")).size());
}
