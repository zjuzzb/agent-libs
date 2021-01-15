#include <gtest.h>
#include <command_line_permissions.h>

TEST(command_line_permissions_test, single_to_string)
{
	command_line_permissions permissions = { CLI_AGENT_STATUS };

	ASSERT_EQ("AGENT_STATUS", permissions.to_string());
}

TEST(command_line_permissions_test, multiple_to_string)
{
	command_line_permissions permissions = {
		CLI_AGENT_INTERNAL_DIAGNOSTICS, 
		CLI_VIEW_CONFIGURATION,
		CLI_VIEW_SENSITIVE_CONFIGURATION};

	ASSERT_EQ("AGENT_INTERNAL_DIAGNOSTICS|VIEW_CONFIGURATION|VIEW_SENSITIVE_CONFIGURATION", permissions.to_string());
}

TEST(command_line_permissions_test, accessable_equal)
{
	command_line_permissions permissions = {
		CLI_AGENT_INTERNAL_DIAGNOSTICS, 
		CLI_VIEW_CONFIGURATION,
		CLI_VIEW_SENSITIVE_CONFIGURATION};

	ASSERT_TRUE(permissions.is_accessable(permissions));
}

TEST(command_line_permissions_test, accessable_over)
{
	command_line_permissions cmd = {
		CLI_AGENT_INTERNAL_DIAGNOSTICS, 
		CLI_VIEW_CONFIGURATION,
		CLI_VIEW_SENSITIVE_CONFIGURATION};

	command_line_permissions client = {
		CLI_AGENT_INTERNAL_DIAGNOSTICS,
		CLI_NETWORK_CALLS_TO_REMOTE_PODS,
		CLI_VIEW_CONFIGURATION,
		CLI_VIEW_SENSITIVE_CONFIGURATION};

	ASSERT_TRUE(cmd.is_accessable(client));
}

TEST(command_line_permissions_test, not_accessable)
{
	command_line_permissions cmd = {
		CLI_AGENT_INTERNAL_DIAGNOSTICS, 
		CLI_VIEW_CONFIGURATION,
		CLI_VIEW_SENSITIVE_CONFIGURATION};

	command_line_permissions client = {
		CLI_AGENT_INTERNAL_DIAGNOSTICS,
		CLI_VIEW_CONFIGURATION};

	ASSERT_FALSE(cmd.is_accessable(client));
}

