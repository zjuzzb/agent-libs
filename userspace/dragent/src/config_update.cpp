/**
 * @file
 *
 * Implementation of config_update.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "config_update.h"
#include "type_config.h"
#include <atomic>
#include <chrono>

namespace
{

type_config<uint16_t> c_max_config_data_wait_seconds(
		30,
		"Maximum time to wait for a CONFIG_DATA message before"
		" initializing security components",
		"security",
		"max_config_data_wait_s");

const std::chrono::time_point<std::chrono::steady_clock> START_TIME =
	std::chrono::steady_clock::now();

std::atomic<bool> s_update_message_received(false);
std::atomic<bool> s_config_updated(false);

}

namespace dragent
{

bool config_update::received()
{
	return s_update_message_received;
}

bool config_update::updated()
{
	return s_config_updated;
}

void config_update::set_updated(const bool updated)
{
	s_update_message_received = true;
	s_config_updated = updated;
}

bool config_update::timed_out()
{
	const auto diff = std::chrono::steady_clock::now() - START_TIME;

	return std::chrono::duration_cast<std::chrono::seconds>(diff).count() >=
	       c_max_config_data_wait_seconds.get_value();
}

} // dragent
