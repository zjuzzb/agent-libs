#include "infrastate_util.h"

draiosproto::container_group test::infra_util::create_cg(const std::string& kind,
							const std::string& id,
							const std::string& ns_name,
							std::vector<std::pair<std::string, std::string>> parents,
							std::vector<std::pair<std::string, std::string>> children)
{
	draiosproto::container_group cg;
	cg.set_namespace_(ns_name);
	cg.mutable_uid()->set_kind(kind);
	cg.mutable_uid()->set_id(id);

	for(const auto& parent : parents)
	{
		auto* p = cg.mutable_parents()->Add();
		p->set_kind(parent.first);
		p->set_id(parent.second);
	}

	for(const auto& child : children)
	{
		auto* c = cg.mutable_children()->Add();
		c->set_kind(child.first);
		c->set_id(child.second);
	}

	return cg;
}

draiosproto::congroup_update_event test::infra_util::create_event(const std::string& kind,
								 const std::string& id,
								 const std::string& ns_name,
								 draiosproto::congroup_event_type type,
								 std::vector<std::pair<std::string, std::string>> parents,
								 std::vector<std::pair<std::string, std::string>> children)
{
	auto evt = draiosproto::congroup_update_event();
	evt.set_type(type);

	evt.mutable_object()->CopyFrom(create_cg(kind, id, ns_name, parents, children));

	return evt;
}

