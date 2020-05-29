#include <gtest.h>
#include "exit_code.h"
#include "running_state.h"
#include "running_state_fixture.h"

using namespace dragent;
using namespace test_helpers;

/**
 * Ensure that restart will report the correct error code.
 */
TEST_F(running_state_fixture, restart)
{
	ASSERT_FALSE(running_state::instance().is_terminated());

	running_state::instance().restart();

	ASSERT_TRUE(running_state::instance().is_terminated());
	ASSERT_EQ(exit_code::RESTART, running_state::instance().exit_code());
	ASSERT_EQ(Poco::Util::Application::EXIT_SOFTWARE, running_state::instance().exit_code());
}

/**
 * Ensure that shut_down will report the correct error code.
 */
TEST_F(running_state_fixture, shut_down)
{
	ASSERT_FALSE(running_state::instance().is_terminated());

	running_state::instance().shut_down();

	ASSERT_TRUE(running_state::instance().is_terminated());
	ASSERT_EQ(exit_code::SHUT_DOWN, running_state::instance().exit_code());
	ASSERT_EQ(Poco::Util::Application::EXIT_OK, running_state::instance().exit_code());
}

/**
 * Ensure that config update will report the correct error code.
 */
TEST_F(running_state_fixture, restart_for_config_update)
{
	ASSERT_FALSE(running_state::instance().is_terminated());

	running_state::instance().restart_for_config_update();

	ASSERT_TRUE(running_state::instance().is_terminated());
	ASSERT_EQ(exit_code::CONFIG_UPDATE, running_state::instance().exit_code());
}

/**
 * Ensure that one call doesn't override another.
 */
TEST_F(running_state_fixture, override_config_update)
{
	ASSERT_FALSE(running_state::instance().is_terminated());

	running_state::instance().restart_for_config_update();
	running_state::instance().shut_down();

	ASSERT_TRUE(running_state::instance().is_terminated());
	ASSERT_EQ(exit_code::CONFIG_UPDATE, running_state::instance().exit_code());
}
