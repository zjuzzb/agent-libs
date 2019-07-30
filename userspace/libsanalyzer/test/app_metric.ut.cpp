/**
 * @file
 *
 * Unit tests for app_metric.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "app_checks.h"
#include "draios.pb.h"
#include <json/json.h>
#include <gtest.h>

/**
 * Ensure that if we try to construct an app_metric with a bucket value that
 * is negative, that construction is successful but the negative metric is
 * dropped.
 */
TEST(app_metric_test, constructor_negative_bucket_value)
{
	const std::string metric_json = R"EOF(
{
    "metrics": [
        "go_ismtpd_debug_ReadGCStats_timer",
        1564156050,
        {
            "0.5": 4779.0,
            "0.95": 1940.0,
            "0.99": 768.0,
            "0.999": 23373.0,
            "Infinity": -29601.0
        },
        {
            "hostname": "ip-10-78-26-174.us-east-2.compute.internal",
            "type": "buckets"
        }
    ]
}
)EOF";
	Json::Value root;
	Json::Reader reader;

	ASSERT_TRUE(reader.parse(metric_json, root));
	Json::Value value = root["metrics"];

	app_metric metric(value);

	draiosproto::app_metric protobuf;

	metric.to_protobuf(&protobuf);

	// Make sure The buckets has only 4 entries; it shouldn't have the
	// "Infinity" entry.
	ASSERT_EQ(4, protobuf.buckets_size());
}
