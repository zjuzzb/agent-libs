#include <gtest.h>
#include "percentile.h"

using namespace std;

//
// based on examples from http://onlinestatbook.com/2/introduction/percentiles.html
//

TEST(percentile, integers)
{
	typedef percentile<int, double> percentile_dt;
	percentile_dt::p_type pctls = {25};
	percentile_dt p(pctls);
	p.add(5);
	p.add(3);
	p.add(8);
	p.add(7);
	p.add(11);
	p.add(9);
	p.add(15);
	p.add(13);
	percentile_dt::p_map_type pctl_map = p.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	auto p_it = pctl_map.begin();
	EXPECT_DOUBLE_EQ(p_it->second, 5.5);

	pctls = {85};
	percentile_dt p1(pctls);
	p1.copy({4,4,5,5,5,5,6,6,6,7,7,7,8,8,9,9,9,10,10,10});
	pctl_map = p1.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_DOUBLE_EQ(p_it->second, 9.85);

	typedef percentile<int> percentile_ft;
	pctls = {50};
	percentile_ft p2(pctls);
	p2.copy({2,3,5,9});
	percentile_ft::p_map_type pctl_map2 = p2.percentiles();
	EXPECT_EQ(pctl_map2.size(), 1);
	auto p_it2 = pctl_map2.begin();
	EXPECT_FLOAT_EQ(p_it2->second, 4.0);

	pctls = {50,75,85,95};
	percentile_ft p3(pctls);
	p3.copy({2,3,5,9,11});
	pctl_map2 = p3.percentiles();
	EXPECT_EQ(pctl_map2.size(), 4);
	p_it2 = pctl_map2.begin();
	EXPECT_FLOAT_EQ(p_it2->second, 5.0);
	++p_it2;
	EXPECT_FLOAT_EQ(p_it2->second, 10.0);
	++p_it2;
	EXPECT_FLOAT_EQ(p_it2->second, 11.0);
	++p_it2;
	EXPECT_FLOAT_EQ(p_it2->second, 11.0);
}
