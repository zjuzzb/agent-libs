#include "k8s_hpa_store.h"
#include "logger.h"
#include "common_logger.h"

COMMON_LOGGER();

k8s_hpa_store::k8s_hpa_store()
{
}

k8s_hpa_store::~k8s_hpa_store() noexcept
{
}


void k8s_hpa_store::handle_add(const k8s_hpa_store::state_key_t& key, k8s_hpa_store::state_t& state)
{
	auto has_key = k8s_object_store::has_key(key, state);
	if(has_key.first)
	{
		draiosproto::container_group& cg = *has_key.second->second.get();
		insert_object_if_eligible(cg);

		if(can_be_hpa_target(cg))
		{
			std::string waiting_hpa_id = lookup_for_waiting_hpa(cg);
			if(!waiting_hpa_id.empty())
			{
				auto key = std::make_pair(k8s_hpa_store::HPA_KIND, std::move(waiting_hpa_id));
				connect_hpa_to_target(key, state);
			}
		}

		if(cg.uid().kind() == k8s_hpa_store::HPA_KIND)
		{
			connect_hpa_to_target(key, state);
		}
	}
}

void k8s_hpa_store::handle_update(const k8s_hpa_store::state_key_t& key, k8s_hpa_store::state_t& state)
{
	handle_delete(key, state);
	handle_add(key, state);
}

void k8s_hpa_store::handle_delete(const state_key_t &key, state_t &state)
{

	auto has_key = k8s_object_store::has_key(key, state);
	if(has_key.first)
	{
		draiosproto::container_group& cg = *has_key.second->second.get();

		const std::string& kind = cg.uid().kind();
		const std::string& id = cg.uid().id();

		if(can_be_hpa_target(cg))
		{
			m_targets.erase(get_cg_kind_and_name(cg));
		}
		else if(kind == HPA_KIND)
		{
			for(auto it = m_hpa_waiting_for_target.begin(); it != m_hpa_waiting_for_target.end(); it++)
			{
				if(it->second == id)
				{
					m_hpa_waiting_for_target.erase(it);
					break;
				}
			}

			// Unlink children in the m_state object
			state[key]->mutable_children()->Clear();
		}
	}
}

void k8s_hpa_store::connect_hpa_to_target(const state_key_t& key, state_t& state)
{
	auto has_key = k8s_object_store::has_key(key, state);
	if(has_key.first)
	{
		draiosproto::container_group& cg = *has_key.second->second.get();

		ASSERT(cg.uid().kind() == HPA_KIND);

		std::pair<std::string, std::string> target_kind_and_name = get_hpa_target_kind_and_name(cg);

		std::string target_id =  lookup_target(target_kind_and_name.first, target_kind_and_name.second);

		if(!target_id.empty())
		{
			// Target event already arrived. So a congrup must be in the state
			auto pos = state.find(std::make_pair(target_kind_and_name.first, target_id));
			ASSERT(pos != state.end());
			if(pos != state.end())
			{
				if(!cg_has_child(cg, k8s_hpa_store::kind_and_name_t(pos->first.first, pos->first.second)))
				{
					draiosproto::congroup_uid* child = cg.mutable_children()->Add();
					child->set_kind(pos->first.first);
					child->set_id(pos->first.second);
					LOG_DEBUG("connected hpa <%s,%s> with child <%s,%s>",
					          cg.uid().kind().c_str(),
					          cg.uid().id().c_str(),
					          child->kind().c_str(),
					          child->id().c_str());
				}
			}
			else
			{
				LOG_WARNING("target <%s,%s> not found in infrastructure state"
					    , target_kind_and_name.first.c_str()
					    , target_kind_and_name.second.c_str());
			}
		}
		else
		{
			// target not arrived yet
			set_hpa_waiting_for_target(cg.uid().id(), std::move(target_kind_and_name));
		}
	}
}

void k8s_hpa_store::insert_potential_target(const std::string& kind, const std::string& name, const std::string& uid)
{
	LOG_DEBUG("inserting <%s,%s,%s> in the store"
		  , kind.c_str()
		  , uid.c_str()
		  , name.c_str());

	m_targets.emplace(std::make_pair(std::make_pair(kind, name), uid));
}

k8s_hpa_store::uid_t k8s_hpa_store::lookup_for_waiting_hpa(const draiosproto::container_group& cg)
{
	k8s_hpa_store::uid_t res;

	if(!can_be_hpa_target(cg))
	{
		return res;
	}

	auto kind_and_name = get_cg_kind_and_name(cg);

	LOG_DEBUG("checking whether an hpa is waiting for <%s,%s>", kind_and_name.first.c_str(), kind_and_name.second.c_str());
	auto pos = m_hpa_waiting_for_target.find(kind_and_name);
	if(pos != m_hpa_waiting_for_target.end())
	{
		res = pos->second;
		m_hpa_waiting_for_target.erase(pos);
		LOG_DEBUG("found hpa %s waiting for target <%s,%s>"
			  , res.c_str()
			  , cg.uid().kind().c_str()
			  , cg.uid().id().c_str());
	}
	return res;
}

bool k8s_hpa_store::cg_has_child(const draiosproto::container_group& cg, const k8s_hpa_store::kind_and_name_t& uid) const
{
	for(const auto& child : cg.children())
	{
		if(k8s_hpa_store::kind_and_name_t(child.kind(), child.id()) == uid)
		{
			return true;
		}
	}
	return false;
}

void k8s_hpa_store::insert_object_if_eligible(const draiosproto::container_group& cg)
{
	const std::string& id = cg.uid().id();

	if(!can_be_hpa_target(cg))
	{
		return;
	}

	auto kind_and_name = get_cg_kind_and_name(cg);
	const auto& cg_name = kind_and_name.second;

	if(!cg_name.empty())
	{
		insert_potential_target(kind_and_name.first, kind_and_name.second, id);
	}
	else
	{
		LOG_WARNING("unable to get kind and name from congroup %s"
			    , cg.DebugString().c_str());
	}
}

k8s_hpa_store::uid_t k8s_hpa_store::lookup_target(const std::string& kind, const std::string& name)
{
	uid_t ret;
	LOG_DEBUG("looking for target <%s,%s> in the store", kind.c_str(), name.c_str());
	auto pos = m_targets.find(std::make_pair(kind, name));
	if(pos != m_targets.end())
	{
		ret = pos->second;
	}

	return ret;
}

void k8s_hpa_store::set_hpa_waiting_for_target(const uid_t& hpa_uid, kind_and_name_t&& target)
{
	LOG_DEBUG("add hpa %s as waiting for target <%s,%s>", hpa_uid.c_str(), target.first.c_str(), target.second.c_str());
	m_hpa_waiting_for_target.emplace(std::make_pair(std::move(target), hpa_uid));
}

bool k8s_hpa_store::has_hpa_waiting_for_target() const
{
	return !m_hpa_waiting_for_target.empty();
}

bool k8s_hpa_store::can_be_hpa_target(const draiosproto::container_group& cg) const
{
	const std::string& kind = cg.uid().kind();
	return kind == k8s_object_store::DEPLOYMENT_KIND
		|| kind == k8s_object_store::REPLICASET_KIND
		|| kind == k8s_object_store::REPLICATION_CONTROLLER_KIND;
}

void k8s_hpa_store::clear()
{
	m_targets.clear();
	m_hpa_waiting_for_target.clear();
}

std::pair<std::string, std::string> k8s_hpa_store::get_hpa_target_kind_and_name(const draiosproto::container_group& cg)
{
	// Ensure this is an hpa
	ASSERT(cg.uid().kind() == k8s_hpa_store::HPA_KIND);

	std::pair<std::string, std::string> ret;
	bool has_kind = false;
	bool has_name = false;
	for(const auto& tag : cg.internal_tags())
	{
		if(tag.first == TARGET_KIND_TAG)
		{
			try
			{
				ret.first = k8s_hpa_store::M_K8S_TO_SYSDIG_KIND.at(tag.second);
				has_kind = true;
			}
			catch (const std::out_of_range& ex)
			{
				LOG_WARNING("Found unknown key: %s", tag.second.c_str());
			}
		}
		else if(tag.first == TARGET_NAME_TAG)
		{
			ret.second = tag.second;
			has_name = true;
		}
		if(has_kind && has_name)
		{
			break;
		}
	}
	if(!has_name)
	{
		LOG_DEBUG("Could not find hpa target name from congroup<%s,%s>", k8s_hpa_store::HPA_KIND.c_str(), cg.uid().id().c_str());
	}
	if(!has_kind)
	{
		LOG_DEBUG("Could not find hpa target kind from congroup<%s,%s>", k8s_hpa_store::HPA_KIND.c_str(), cg.uid().id().c_str());
	}
	return ret;
}

uint64_t k8s_hpa_store::size() const
{
	return m_targets.size() +  m_hpa_waiting_for_target.size();
}

void k8s_hpa_store::print_store_status() const
{
	LOG_DEBUG("targets: %ld - hpa: %ld"
		  , m_targets.size()
		  , m_hpa_waiting_for_target.size());
}
