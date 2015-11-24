//
// k8s_state.cpp
//

#include "mesos_state.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include <sstream>
#include <iostream>

//
// state
//

mesos_state::mesos_state(bool is_captured) : m_is_captured(is_captured)
{
}
