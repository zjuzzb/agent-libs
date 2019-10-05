#include <gtest.h>
#include "protocol_handler.h"

TEST(protocol_handler_test, config)
{
	std::string config = R"(
protobuf_print: true
compression:
  enabled: false
audit_tap:
  debug_only: false
)";
	yaml_configuration config_yaml(config);
        ASSERT_EQ(0, config_yaml.errors().size());

	protocol_handler::c_print_protobuf.init(config_yaml);
	protocol_handler::c_compression_enabled.init(config_yaml);
	protocol_handler::c_audit_tap_debug_only.init(config_yaml);

	ASSERT_EQ(protocol_handler::c_print_protobuf.get_value(), true);
	ASSERT_EQ(protocol_handler::c_compression_enabled.get_value(), false);
	ASSERT_EQ(protocol_handler::c_audit_tap_debug_only.get_value(), false);
}
