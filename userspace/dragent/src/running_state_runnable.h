#pragma once

#include "running_state.h"
#include "watchdog_runnable.h"
#include <functional>

namespace dragent
{

/**
 * A runnable that terminates based on the running_state
 */
class running_state_runnable : public watchdog_runnable
{
public:
	running_state_runnable(const std::string &name) :
	      watchdog_runnable(name, 
	                        std::bind(&running_state::is_terminated, 
	                                  &running_state::instance()))
	{}
};

}
