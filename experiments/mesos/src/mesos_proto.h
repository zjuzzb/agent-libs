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
	mesos_proto(draiosproto::metrics& metrics);

	~mesos_proto();

	const draiosproto::mesos_state& get_proto(const mesos_state_t& state);

private:
	void make_protobuf(const mesos_state_t& state);
	void extract_groups(const marathon_group::group_map_t& groups);

	template <typename V, typename C>
	void populate_component(V& component, C* mesos_component)
	{
		draiosproto::mesos_common* common = mesos_component->mutable_common();
		common->set_name(component.get_name());
		common->set_uid(component.get_uid());

		for (auto label : component.get_labels())
		{
			draiosproto::mesos_pair* lbl = common->add_labels();
			lbl->set_key(label.first);
			lbl->set_value(label.second);
		}
	}
	
	draiosproto::mesos_state& m_proto;
};
