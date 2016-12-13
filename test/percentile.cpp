#include <gtest.h>
#include "percentile.h"

using namespace std;

TEST(percentile, integers)
{
	std::vector<int> pctls = {25};
	percentile p(pctls);
	p.add(5);
	p.add(3);
	p.add(8);
	p.add(7);
	p.add(11);
	p.add(9);
	p.add(15);
	p.add(13);
	percentile::p_map_type pctl_map = p.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	auto p_it = pctl_map.begin();
	EXPECT_DOUBLE_EQ(p_it->second, 5.);

	pctls = {85};
	percentile p1(pctls);
	p1.copy(std::vector<int>({4,4,5,5,5,5,6,6,6,7,7,7,8,8,9,9,9,10,10,10}));
	pctl_map = p1.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_DOUBLE_EQ(p_it->second, 9.);

	pctls = {50};
	percentile p2(pctls);
	p2.copy(std::vector<int>({2,3,5,9}));
	pctl_map = p2.percentiles();
	EXPECT_EQ(pctl_map.size(), 1);
	p_it = pctl_map.begin();
	EXPECT_FLOAT_EQ(p_it->second, 3.);

	pctls = {50,75,85,95};
	percentile p3(pctls);
	p3.copy(std::vector<int>({2,3,5,9,11}));
	pctl_map = p3.percentiles();
	EXPECT_EQ(pctl_map.size(), 4);
	p_it = pctl_map.begin();
	EXPECT_FLOAT_EQ(p_it->second, 5.);
	++p_it;
	EXPECT_FLOAT_EQ(p_it->second, 9.);
	++p_it;
	EXPECT_FLOAT_EQ(p_it->second, 11.);
	++p_it;
	EXPECT_FLOAT_EQ(p_it->second, 11.);
}
