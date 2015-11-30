//
// mesos.h
//

#pragma once

#include "json/json.h"
#include "mesos_common.h"
#include "mesos_component.h"
#include "mesos_http.h"
#include "mesos_state.h"
#include "uri.h"
#include <sstream>
#include <utility>

class mesos
{
public:
	mesos(const std::string& uri = "http://localhost:5050",
		const std::string& api = "/state.json");

	~mesos();

	const mesos_state_t get_state() const;

private:
	void parse_json(const std::string& json);
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& task);
	void add_labels(mesos_task& task, const Json::Value& t_val);

	mesos_http    m_http;
	mesos_state_t m_state;

	static const mesos_component::component_map m_components;
};

inline const mesos_state_t mesos::get_state() const
{
	return m_state;
}
