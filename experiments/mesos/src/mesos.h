//
// mesos.h
//

#pragma once

#include "json/json.h"
#include "mesos_common.h"
#include "mesos_component.h"
#include "mesos_state.h"
#include <sstream>
#include <utility>

class mesos
{
public:
	mesos(const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	~mesos();

private:
	mesos_state_s  m_state;

	static const mesos_component::component_map m_components;
};


