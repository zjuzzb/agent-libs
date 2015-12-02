//
// mesos_proto.cpp
//

#include "mesos_proto.h"
#include "mesos_component.h"
#include "mesos_state.h"
#include "draios.pb.h"

//using namespace draiosproto;

mesos_proto::mesos_proto(draiosproto::metrics& met) : m_proto(*met.mutable_mesos())
{
}

mesos_proto::~mesos_proto()
{
}

const draiosproto::mesos_state& mesos_proto::get_proto(const mesos_state_t& state)
{
	make_protobuf(state);
	return m_proto;
}

void mesos_proto::make_protobuf(const mesos_state_t& state)
{
	for (auto& framework : state.get_frameworks())
	{
		draiosproto::mesos_framework* frameworks = m_proto.add_frameworks();
		populate_component(framework, frameworks);
		for (auto& task_pair : framework.get_tasks())
		{
			auto task = frameworks->add_tasks();
			task->mutable_common()->set_uid(task_pair.first);
			task->mutable_common()->set_name(task_pair.second->get_name());

			for(auto& lbl_pair : task_pair.second->get_labels())
			{
				auto label = task->mutable_common()->add_labels();
				label->set_key(lbl_pair.first);
				label->set_value(lbl_pair.second);
			}
		}
	}
}
