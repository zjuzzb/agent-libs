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
	enum node_t
	{
		NODE_MASTER,
		NODE_SLAVE
	};

	mesos(const std::string& uri = "http://localhost:5050",
		const std::string& api = "/state.json");

	~mesos();

	node_t get_node_type() const;
	const mesos_state_t get_state() const;

private:
	void parse_json(const std::string& json);
	void determine_node_type(const Json::Value& root);
	bool is_master() const;
	void add_framework(const Json::Value& framework);
	void add_tasks(mesos_framework& framework, const Json::Value& f_val);
	void add_tasks_impl(mesos_framework& framework, const Json::Value& tasks);
	void add_labels(std::shared_ptr<mesos_task> task, const Json::Value& t_val);

	std::string   m_container_id;
	node_t        m_node_type;
	mesos_http    m_http;
	mesos_state_t m_state;

	static const mesos_component::component_map m_components;
};

inline mesos::node_t mesos::get_node_type() const
{
	return m_node_type;
}

inline const mesos_state_t mesos::get_state() const
{
	return m_state;
}

inline bool mesos::is_master() const
{
	return m_node_type == NODE_MASTER;
}
