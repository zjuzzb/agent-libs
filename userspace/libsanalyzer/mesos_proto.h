//
// mesos_proto.h
//
// extracts needed data from the mesos_proto interface
//

#pragma once

#include "draios.pb.h"
#include "google/protobuf/text_format.h"
#include "marathon_component.h"

class mesos_state_t;

class mesos_proto
{
public:
	mesos_proto(draiosproto::metrics& metrics, const mesos_state_t& state, const std::set<std::string> &marathon_skip_labels);

	~mesos_proto();

	const draiosproto::mesos_state& get_proto();

private:
	void make_protobuf();
	void extract_groups(const marathon_group::group_map_t& groups,
		draiosproto::marathon_group* to_group = 0);

	template <typename V, typename C>
	void populate_component(V& component, C* mesos_component, const std::string& marathon_uri = "")
	{
		draiosproto::mesos_common* common = mesos_component->mutable_common();
		const std::string& c_name = component.get_name();
		common->set_name(marathon_uri.empty() ? c_name : (std::string(c_name).append(" [").append(marathon_uri).append(1, ']')));
		common->set_uid(component.get_uid());

		for (auto label : component.get_labels())
		{
			draiosproto::mesos_pair* lbl = common->add_labels();
			lbl->set_key(label.first);
			lbl->set_value(label.second);
		}
	}

	draiosproto::mesos_state& m_proto;
	const mesos_state_t&      m_state;
	const std::set<std::string> &m_marathon_skip_labels;
};
