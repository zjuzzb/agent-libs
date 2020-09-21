#pragma once

#include <cstdint>

/**
 * The current time returned in various units. This is called 
 * wall time to compare it to a clock on the wall. This means 
 * that time can go backwards if an operator changes the time. 
 * This makes it un-ideal for timers that need to be monotonic.
 */
namespace wall_time
{

/**
 * @return uint64_t the wall time in nanoseconds
 */
uint64_t nanoseconds();

/**
 * @return uint64_t the wall time in seconds
 */
uint64_t seconds();

}

