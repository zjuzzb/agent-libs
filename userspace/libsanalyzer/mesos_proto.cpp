//
// mesos_proto.cpp
//

#include "mesos_proto.h"
#include "mesos_component.h"
#include "mesos_state.h"
#include "uri.h"
#include "draios.pb.h"

mesos_proto::mesos_proto(draiosproto::metrics& met, const mesos_state_t& state) : m_proto(*met.mutable_mesos()), m_state(state)
{
}

mesos_proto::~mesos_proto()
{
}

const draiosproto::mesos_state& mesos_proto::get_proto()
{
	make_protobuf();
	return m_proto;
}

void mesos_proto::make_protobuf()
{
	std::string marathon_uri;
	for (const auto& framework : m_state.get_frameworks())
	{
		if(framework.get_name() == mesos_framework::MARATHON_ROOT_NAME)
		{
			marathon_uri = m_state.get_marathon_uri();
			if(!marathon_uri.empty())
			{
				uri url(marathon_uri);
				marathon_uri = url.get_host();
				marathon_uri.append(1, ':').append(std::to_string(url.get_port()));
			}
		}
		else { marathon_uri.clear(); }
		draiosproto::mesos_framework* frameworks = m_proto.add_frameworks();
		populate_component(framework, frameworks, marathon_uri);
		for (auto& task_pair : framework.get_tasks())
		{
			auto task = frameworks->add_tasks();
			task->mutable_common()->set_uid(task_pair.first);
			task->mutable_common()->set_name(task_pair.second->get_name());
			task->set_slave_id(task_pair.second->get_slave_id());

			for(auto& lbl_pair : task_pair.second->get_labels())
			{
				auto label = task->mutable_common()->add_labels();
				label->set_key(lbl_pair.first);
				label->set_value(lbl_pair.second);
			}
		}
	}

	for(const auto& slave : m_state.get_slaves())
	{
		draiosproto::mesos_slave* slaves = m_proto.add_slaves();
		populate_component(slave, slaves);
	}

	extract_groups(m_state.get_groups());
}

void mesos_proto::extract_groups(const marathon_group::group_map_t& groups, draiosproto::marathon_group* to_group)
{
	for(const auto& group : groups)
	{
		to_group = to_group ? to_group->add_groups() : m_proto.add_groups();
		to_group->set_id(group.first);
		for(const auto& app : group.second->get_apps())
		{
			draiosproto::marathon_app* a = to_group->add_apps();
			a->set_id(app.first);
			for(const auto& task : app.second->get_tasks())
			{
				std::string* t = a->add_task_ids();
				*t = task;
			}
		}
		const marathon_group::group_map_t& g_groups = group.second->get_groups();
		if(g_groups.size())
		{
			extract_groups(g_groups, to_group);
		}
	}
}
