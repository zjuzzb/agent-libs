/**
 * @file
 *
 * Unit tests for object filter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "analyzer_fd.h"
#include "configuration_manager.h"
#include "feature_manager.h"
#include "parser_http.h"
#include "protocol_manager.h"
#include "scoped_config.h"
#include "scoped_configuration.h"

#include <gtest.h>

using namespace test_helpers;

TEST(port_list_config, init)
{
	std::string yaml_string = R"(known_ports:
  - 23
  - 37
)";

	scoped_configuration config(yaml_string);
	EXPECT_TRUE(config.loaded());
	const port_list_config* known_ports = dynamic_cast<const port_list_config*>(
	    configuration_manager::instance().get_configuration_unit("known_ports"));
	ASSERT_NE(known_ports, nullptr);
	EXPECT_EQ(known_ports->value_to_string(), "Count: 2");
	EXPECT_TRUE(known_ports->get_value().test(23));
	EXPECT_TRUE(known_ports->get_value().test(37));
	EXPECT_FALSE(known_ports->get_value().test(5));
	EXPECT_FALSE(known_ports->get_value().test(84));
}

TEST(protocol_manager, disabled)
{
	scoped_config<bool> config("feature.protocol_stats", false);
	scoped_config<bool> config2("feature.protocol_stats_opt.force", true);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	auto type = protocol_manager::instance().detect_proto(nullptr,
	                                                      &trinfo,
	                                                      sinsp_partial_transaction::DIR_OUT,
	                                                      nullptr,
	                                                      0);
	EXPECT_EQ(type, sinsp_partial_transaction::TYPE_UNKNOWN);
}

TEST(protocol_manager, http_enabled)
{
	scoped_config<bool> config("feature.http_stats", true);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t* buf = (const uint8_t*)"GET ";
	ASSERT_TRUE(protocol_http::instance()
	                .is_protocol(nullptr, &trinfo, sinsp_partial_transaction::DIR_OUT, buf, 4, 0));
}

TEST(protocol_manager, http_disabled)
{
	scoped_config<bool> config("feature.http_stats", false);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t* buf = (const uint8_t*)"GET ";
	ASSERT_FALSE(protocol_http::instance()
	                 .is_protocol(nullptr, &trinfo, sinsp_partial_transaction::DIR_OUT, buf, 4, 0));
}

TEST(protocol_manager, mysql_enabled)
{
	scoped_config<bool> config("feature.mysql_stats", true);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t buf[6] = {0};
	*(uint16_t*)buf = 2;
	ASSERT_TRUE(protocol_mysql::instance().is_protocol(nullptr,
	                                                   &trinfo,
	                                                   sinsp_partial_transaction::DIR_OUT,
	                                                   buf,
	                                                   6,
	                                                   SRV_PORT_MYSQL));
}

TEST(protocol_manager, mysql_disabled)
{
	scoped_config<bool> config("feature.mysql_stats", false);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t buf[6] = {0};
	*(uint16_t*)buf = 2;
	ASSERT_FALSE(protocol_mysql::instance().is_protocol(nullptr,
	                                                    &trinfo,
	                                                    sinsp_partial_transaction::DIR_OUT,
	                                                    buf,
	                                                    6,
	                                                    SRV_PORT_MYSQL));
}

TEST(protocol_manager, postgres_enabled)
{
	scoped_config<bool> config("feature.postgres_stats", true);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t buf[8] = {0};
	*(uint32_t*)(buf + sizeof(uint32_t)) = 0x00000300;
	ASSERT_TRUE(protocol_postgres::instance().is_protocol(nullptr,
	                                                      &trinfo,
	                                                      sinsp_partial_transaction::DIR_OUT,
	                                                      buf,
	                                                      8,
	                                                      SRV_PORT_POSTGRES));
}

TEST(protocol_manager, postgres_disabled)
{
	scoped_config<bool> config("feature.postgres_stats", false);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t buf[8] = {0};
	*(uint32_t*)(buf + sizeof(uint32_t)) = 0x00000300;
	ASSERT_FALSE(protocol_postgres::instance().is_protocol(nullptr,
	                                                       &trinfo,
	                                                       sinsp_partial_transaction::DIR_OUT,
	                                                       buf,
	                                                       8,
	                                                       SRV_PORT_POSTGRES));
}

TEST(protocol_manager, mongodb_enabled)
{
	scoped_config<bool> config("feature.mongodb_stats", true);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t buf[16] = {0};
	*(int32_t*)(buf + 12) = 1;
	ASSERT_TRUE(protocol_mongodb::instance()
	                .is_protocol(nullptr, &trinfo, sinsp_partial_transaction::DIR_OUT, buf, 16, 0));
}

TEST(protocol_manager, mongodb_disabled)
{
	scoped_config<bool> config("feature.mongodb_stats", false);
	ASSERT_TRUE(feature_manager::instance().initialize(feature_manager::AGENT_VARIANT_TRADITIONAL));

	sinsp_partial_transaction trinfo;
	const uint8_t buf[16] = {0};
	*(int32_t*)(buf + 12) = 1;
	ASSERT_FALSE(
	    protocol_mongodb::instance()
	        .is_protocol(nullptr, &trinfo, sinsp_partial_transaction::DIR_OUT, buf, 16, 0));
}
