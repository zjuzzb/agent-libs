#include <gtest.h>
#include "handshake.pb.h"
#include "handshake_helpers.h"

using namespace draiosproto;

TEST(handshake_helpers_test, metric_limit_to_uint32)
{
	ASSERT_EQ(10000, handshake_helpers::metric_limit_to_uint32(custom_metric_limit_value::CUSTOM_METRIC_DEFAULT));
	ASSERT_EQ(10000, handshake_helpers::metric_limit_to_uint32(custom_metric_limit_value::CUSTOM_METRIC_10k));
	ASSERT_EQ(20000, handshake_helpers::metric_limit_to_uint32(custom_metric_limit_value::CUSTOM_METRIC_20k));
	ASSERT_EQ(50000, handshake_helpers::metric_limit_to_uint32(custom_metric_limit_value::CUSTOM_METRIC_50k));
	ASSERT_EQ(100000, handshake_helpers::metric_limit_to_uint32(custom_metric_limit_value::CUSTOM_METRIC_100k));
}
