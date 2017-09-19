#include <gtest.h>
#include "percentile.h"

extern "C"
{
	#include "cm_quantile.h"
}

using namespace std;

TEST(percentile, integers)
{
	std::set<double> pctls = {25};
	percentile p(pctls);
	p.add(5);
	p.add(3);
	p.add(8);
	p.add(7);
	p.add(11);
	p.add(9);
	p.add(15);
	p.add(13);
	EXPECT_EQ(p.sample_count(), 8);
	percentile::p_map_type pctl_map = p.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	auto p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first, 25);
	EXPECT_DOUBLE_EQ(p_it->second, 6.);

	percentile pc(p);
	EXPECT_EQ(pc.sample_count(), 8);
	pctl_map = pc.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first, 25);
	EXPECT_DOUBLE_EQ(p_it->second, 6.);

	pctls = {85};
	percentile p1(pctls);
	p1.copy(std::vector<int>({4,4,5,5,5,5,6,6,6,7,7,7,8,8,9,9,9,10,10,10}));
	EXPECT_EQ(p1.sample_count(), 20);
	pctl_map = p1.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first, 85);
	EXPECT_DOUBLE_EQ(p_it->second, 9.5);

	pc = p1;
	EXPECT_EQ(pc.sample_count(), 20);
	pctl_map = pc.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first, 85);
	EXPECT_DOUBLE_EQ(p_it->second, 9.5);

	pctls = {50};
	percentile p2(pctls);
	p2.copy(std::vector<int>({2,3,5,9}));
	EXPECT_EQ(p2.sample_count(), 4);
	pctl_map = p2.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first,50);
	EXPECT_FLOAT_EQ(p_it->second, 4.);

	pctls = {50,75,85,95};
	percentile p3(pctls);
	p3.copy(std::vector<int>({2,3,5,9,11}));
	EXPECT_EQ(p3.sample_count(), 5);
	pctl_map = p3.percentiles();
	EXPECT_EQ(pctl_map.size(), 4);
	p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first, 50);
	EXPECT_FLOAT_EQ(p_it->second, 5.);
	++p_it;
	EXPECT_EQ(p_it->first, 75);
	EXPECT_FLOAT_EQ(p_it->second, 9.5);
	++p_it;
	EXPECT_EQ(p_it->first, 85);
	EXPECT_FLOAT_EQ(p_it->second, 10.5);
	++p_it;
	EXPECT_EQ(p_it->first, 95);
	EXPECT_FLOAT_EQ(p_it->second, 11.);
}

TEST(percentile, doubles)
{
	std::set<double> pctls = {25};
	percentile p(pctls);
	p.add(5.3);
	p.add(3.8);
	p.add(8.7);
	p.add(7.11);
	p.add(11.9);
	p.add(9.15);
	p.add(15.13);
	p.add(13.5);
	EXPECT_EQ(p.sample_count(), 8);
	percentile::p_map_type pctl_map = p.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	auto p_it = pctl_map.begin();
	EXPECT_EQ(p_it->first, 25);
	EXPECT_DOUBLE_EQ(p_it->second, 6.205);
}

TEST(percentile, randoms)
{
    cm_quantile cm;
    double quants[] = {0.5, 0.90, 0.99};
    int res = init_cm_quantile(0.01, (double*)&quants, 3, &cm);
    ASSERT_TRUE(res == 0);

    srandom(42);
    for (int i=0; i < 100000; i++) {
        res = cm_add_sample(&cm, random());
        ASSERT_TRUE(res == 0);
    }

    res = cm_flush(&cm);
    ASSERT_TRUE(res == 0);

    double val = cm_query(&cm, 0.5);
    ASSERT_TRUE(val >= 1073741823 - 21474836 && val <= 1073741823 + 21474836);

    val = cm_query(&cm, 0.90);
    ASSERT_TRUE(val >= 1932735282 - 21474836 && val <= 1932735282 + 21474836);

    val = cm_query(&cm, 0.99);
    ASSERT_TRUE(val >= 2126008810 - 21474836 && val <= 2126008810 + 21474836);

    res = destroy_cm_quantile(&cm);
    ASSERT_TRUE(res == 0);
}

TEST(percentile, random)
{
	std::set<double> quants = {50, 90, 99};
	percentile p(quants);
	EXPECT_EQ(p.percentiles().size(), 3);

	srandom(42);
	for (int i=0; i < 100000; i++)
	{
		p.add(random());
	}
	EXPECT_EQ(p.sample_count(), 100000);

	percentile::p_map_type pctl_map = p.percentiles();

	double val = pctl_map[50];
	EXPECT_GE(val, 1073741823 - 21474836);
	EXPECT_LE(val, 1073741823 + 21474836);

	val = pctl_map[90];
	EXPECT_GE(val, 1932735282 - 21474836);
	EXPECT_LE(val, 1932735282 + 21474836);

	val = pctl_map[99];
	EXPECT_GE(val, 2126008810 - 21474836);
	EXPECT_LE(val, 2126008810 + 21474836);

	p.reset();
	EXPECT_EQ(p.percentiles().size(), 3);

	for (int i=0; i < 100000; i++)
	{
		p.add(random());
	}
	EXPECT_EQ(p.sample_count(), 100000);

	val = pctl_map[50];
	EXPECT_GE(val, 1073741823 - 21474836);
	EXPECT_LE(val, 1073741823 + 21474836);

	val = pctl_map[90];
	EXPECT_GE(val, 1932735282 - 21474836);
	EXPECT_LE(val, 1932735282 + 21474836);

	val = pctl_map[99];
	EXPECT_GE(val, 2126008810 - 21474836);
	EXPECT_LE(val, 2126008810 + 21474836);
}
