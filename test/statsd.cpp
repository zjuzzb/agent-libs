//
// Created by Luca Marturana on 31/03/15.
//

#include <gtest.h>
#include "sys_call_test.h"
#include "statsite_proxy.h"

/* statsite output:

counts.mycounter#xxx,yy|42.000000|1427796784
timers.myhist#we,ff.sum|31890.000000|1427796784
timers.myhist#we,ff.sum_sq|19643496.000000|1427796784
timers.myhist#we,ff.mean|475.970149|1427796784
timers.myhist#we,ff.lower|6.000000|1427796784
timers.myhist#we,ff.upper|894.000000|1427796784
timers.myhist#we,ff.count|67|1427796784
timers.myhist#we,ff.stdev|260.093455|1427796784
timers.myhist#we,ff.median|479.000000|1427796784
timers.myhist#we,ff.p50|479.000000|1427796784
timers.myhist#we,ff.p95|888.000000|1427796784
timers.myhist#we,ff.p99|894.000000|1427796784
timers.myhist#we,ff.rate|31890.000000|1427796784
timers.myhist#we,ff.sample_rate|67.000000|1427796784
timers.mytime.sum|6681.000000|1427796784
timers.mytime.sum_sq|853697.000000|1427796784
timers.mytime.mean|99.716418|1427796784
timers.mytime.lower|0.000000|1427796784
timers.mytime.upper|197.000000|1427796784
timers.mytime.count|67|1427796784
timers.mytime.stdev|53.298987|1427796784
timers.mytime.median|106.000000|1427796784
timers.mytime.p50|106.000000|1427796784
timers.mytime.p95|190.000000|1427796784
timers.mytime.p99|197.000000|1427796784
timers.mytime.rate|6681.000000|1427796784
timers.mytime.sample_rate|67.000000|1427796784
gauges.mygauge|2.000000|1427796784
sets.myset|53|1427796784

*/
TEST(statsd_metric, parse_counter)
{
	auto metric = statsd_metric();
	metric.parse_line("counts.mycounter#xxx,yy|42.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("mycounter", metric.name());
	EXPECT_EQ(statsd_metric::type_t::COUNT, metric.type());
	EXPECT_DOUBLE_EQ(42.0, metric.value());
	EXPECT_TRUE(metric.tags().find("xxx") != metric.tags().end());
	EXPECT_FALSE(metric.parse_line("counts.mycounter#xxx,yy|42.000000|1427796785\n"));

	metric = statsd_metric();
	metric.parse_line("counts.mycounter|42.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("mycounter", metric.name());
	EXPECT_DOUBLE_EQ(42.0, metric.value());
	EXPECT_EQ(statsd_metric::type_t::COUNT, metric.type());

	metric = statsd_metric();
	metric.parse_line("counts.mycounter.amazing|42.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("mycounter.amazing", metric.name());
}

TEST(statsd_metric, parser_histogram)
{
	auto metric = statsd_metric();
	metric.parse_line("timers.mytime.sum|6681.000000|1427796784\n");
	metric.parse_line("timers.mytime.median|106.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("mytime", metric.name());
	EXPECT_DOUBLE_EQ(6681.0, metric.sum());
	EXPECT_DOUBLE_EQ(106.0, metric.median());
	EXPECT_EQ("", metric.container_id());
	EXPECT_FALSE(metric.parse_line("timers.mytime#we,ff.sum|6681.000000|1427796784\n"));

	metric = statsd_metric();
	metric.parse_line("timers.mytime#we,ff.sum|6681.000000|1427796784\n");
	EXPECT_EQ("mytime", metric.name());
	EXPECT_DOUBLE_EQ(6681.0, metric.sum());
	EXPECT_EQ("", metric.container_id());

	metric = statsd_metric();
	metric.parse_line("timers.lksajdlkjsal$mytime#we=ff.sum|6681.000000|1427796784\n");
	EXPECT_EQ("mytime", metric.name());
	EXPECT_DOUBLE_EQ(6681.0, metric.sum());
	EXPECT_EQ("ff", metric.tags().at("we"));
	EXPECT_EQ("lksajdlkjsal", metric.container_id());
}

TEST(statsd_metric, parser_gauge)
{
	auto metric = statsd_metric();
	metric.parse_line("gauges.mygauge|2.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("mygauge", metric.name());
	EXPECT_DOUBLE_EQ(2.0, metric.value());
	EXPECT_EQ("", metric.container_id());
}

TEST(statsd_metric, parser_edge_cases)
{
	auto metric = statsd_metric();
	metric.parse_line("gauges.mygauge#|2.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("mygauge", metric.name());
	EXPECT_DOUBLE_EQ(2.0, metric.value());

	metric = statsd_metric();
	metric.parse_line("gauges.#|2.000000|1427796784\n");
	EXPECT_EQ(1427796784, metric.timestamp());
	EXPECT_EQ("", metric.name());
	EXPECT_DOUBLE_EQ(2.0, metric.value());
}

TEST(statsite_proxy, parser)
{
	auto output_file = fopen("resources/statsite_output.txt", "r");
	auto input_fd = fopen("/dev/null", "w");
	ASSERT_TRUE(output_file != NULL);
	statsite_proxy proxy(make_pair(input_fd, output_file));

	auto ret = proxy.read_metrics();
	EXPECT_EQ(10, ret.at("").size());
	EXPECT_EQ(10, ret.at("3ce9120d8307").size());

	set<string> reference_set;
	for(unsigned j = 1; j < 11; ++j)
	{
		reference_set.insert(string("totam.sunt.consequatur.numquam.aperiam") + to_string(j));
	}
	for(const auto& item : ret)
	{
		set<string> found_set;
		for(const auto& m : item.second)
		{
			found_set.insert(m.name());
		}
		for(const auto& ref : reference_set)
		{
			EXPECT_TRUE(found_set.find(ref) != found_set.end()) << ref << " not found for " << item.first;
		}
	}
	fclose(output_file);
	fclose(input_fd);
}