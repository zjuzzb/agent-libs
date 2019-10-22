/**
 * @file
 *
 * Interface to config_update.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

namespace dragent {

/**
 * Manages state related to whether or not the agent has received the
 * CONFIG_DATA message from the backend, and if so if that message resulted
 * in a config change.
 */
namespace config_update {

/**
 * Returns true if the agent has received a CONFIG_DATA message from the
 * backend, false otherwise.
 */
bool received();

/**
 * Returns true if the agent has received a CONFIG_DATA message from the
 * backend, and that message resulted in a config change, false otherwise.
 */
bool updated();

/**
 * Notifies config_update that a CONFIG_DATA message was received.
 *
 * @param[in] updated true if the CONFIG_DATA resulted in a config change,
 *                    false otherwise.
 */
void set_updated(bool updated);

/**
 * Returns true if more than the configured wait time for the initial
 * CONFIG_DATA message has passed, false otherwise.  Note the value of
 * received() does not affect this operation.
 *
 */
bool timed_out();

} // namespace config_update
} // dragent
