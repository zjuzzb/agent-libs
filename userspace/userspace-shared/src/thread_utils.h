/**
 * @file
 *
 * Interface to thread-related helper APIs.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <sys/types.h>

namespace thread_utils
{

/**
 * Returns the Linux thread ID of the calling thread.
 */
pid_t get_tid();

} // end thread_utils
