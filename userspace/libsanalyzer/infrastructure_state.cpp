#include <algorithm>

#include "infrastructure_state.h"

infrastructure_state::infrastructure_state(uint64_t refresh_interval) :
	m_interval(refresh_interval)
{
	m_callback = [this] (bool successful, google::protobuf::Message *response_msg) {
		sdc_internal::congroup_update_event *evt = (sdc_internal::congroup_update_event *)response_msg;

		handle_event(evt);
	};

	glogf(sinsp_logger::SEV_DEBUG, "Sending Request for orchestrator events.");
	m_coclient.get_orchestrator_events(m_callback);
}

infrastructure_state::~infrastructure_state(){}

void infrastructure_state::refresh()
{
	m_interval.run([this]()
	{
		m_coclient.next();
	});
}

void infrastructure_state::handle_event(sdc_internal::congroup_update_event *evt)
{
	std::string kind = evt->object().uid().kind();
	std::string id = evt->object().uid().id();

	glogf(sinsp_logger::SEV_DEBUG, "Handling event with uid <%s,%s>", kind.c_str(), id.c_str());

	auto key = make_pair(kind, id);

	bool is_present = m_state.find(key) != m_state.end();
	if(!is_present) {
		switch(evt->type()) {
		case sdc_internal::ADDED:
			m_state[key] = make_unique<draiosproto::container_group>();
			m_state[key]->CopyFrom(evt->object());
			connect(key);
			break;
		case sdc_internal::REMOVED:
			throw new sinsp_exception("Cannot remove container_group with id " + id + " because it does not exists.");
			break;
		case sdc_internal::UPDATED:
			throw new sinsp_exception("Cannot update container_group with id " + id + " because it does not exists.");
			break;
		}
	} else {
		switch(evt->type()) {
		case sdc_internal::ADDED:
			throw new sinsp_exception("Cannot add container_group with id " + id + " because it's already present.");
			break;
		case sdc_internal::REMOVED:
			remove(evt);
			break;
		case sdc_internal::UPDATED:
			*m_state[key]->mutable_tags() = evt->object().tags();
			m_state[key]->mutable_ip_addresses()->CopyFrom(evt->object().ip_addresses());
			m_state[key]->mutable_ports()->CopyFrom(evt->object().ports());
			*m_state[key]->mutable_metrics() = evt->object().metrics();
			break;
		}
	}

	glogf(sinsp_logger::SEV_DEBUG, "Event with uid <%s,%s> handled. Current state size: %d", kind.c_str(), id.c_str(), m_state.size());
}

void infrastructure_state::connect(infrastructure_state::uid_t& key)
{
	//
	// Connect the new group to the parents
	//
	for (auto x : m_state[key]->parents()) {
		auto pkey = make_pair(x.kind(), x.id());
		draiosproto::congroup_uid *child = m_state[pkey]->mutable_children()->Add();
		child->set_kind(key.first);
		child->set_id(key.second);
		glogf(sinsp_logger::SEV_DEBUG, "child <%s,%s> added to <%s,%s>",
			  key.first.c_str(), key.second.c_str(), pkey.first.c_str(), pkey.second.c_str());
	}
}

void infrastructure_state::remove(sdc_internal::congroup_update_event *evt)
{
	//
	// Remove all children references to this group
	//
	auto key = make_pair(evt->object().uid().kind(), evt->object().uid().id());
	glogf(sinsp_logger::SEV_DEBUG, "Remove container group <%s,%s>", key.first.c_str(), key.second.c_str());

	for (auto x : m_state[key]->parents()) {
		auto pkey = make_pair(x.kind(), x.id());
		auto pos = m_state[pkey]->children().begin();
		bool erased = false;
		glogf(sinsp_logger::SEV_DEBUG, "Searching children link inside container group <%s,%s>", pkey.first.c_str(), pkey.second.c_str());

		for (; pos != m_state[pkey]->children().end(); ++pos) {
			if (pos->kind() == evt->object().uid().kind() &&
				pos->id() == evt->object().uid().id()) {
				glogf(sinsp_logger::SEV_DEBUG, "Erase children link from <%s,%s>", pkey.first.c_str(), pkey.second.c_str());
				m_state[pkey]->mutable_children()->erase(pos);
				glogf(sinsp_logger::SEV_DEBUG, "Erased.");
				erased = true;
				break;
			}
		}
		if (!erased) {
			glogf(sinsp_logger::SEV_DEBUG, "Error. Container groups inconsistency detected.");
			throw new sinsp_exception("Container groups inconsistency detected. "
									  "<" + m_state[key]->uid().kind() + "," + m_state[key]->uid().id() +
									  "> should be a child of <" + m_state[pkey]->uid().kind() + "," +
									  m_state[pkey]->uid().id() + ">");
		}
	}

	//
	// Delete also the container children
	//
	for (auto x : m_state[key]->children()) {
		if (x.kind() == "container") {
			glogf(sinsp_logger::SEV_DEBUG, "Erase container children <%s,%s>", x.kind().c_str(), x.id().c_str());
			m_state.erase(make_pair(x.kind(), x.id()));
		}
	}

	// Remove the group itself
	m_state.erase(key);
}

bool infrastructure_state::walk_and_match(draiosproto::container_group *congroup,
										google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &preds,
										std::unordered_set<uid_t> &visited_groups)
{
	auto evaluate = [](draiosproto::scope_predicate p, const std::string value)
	{
		// KISS for now

		bool ret;
		switch(p.op()) {
		case draiosproto::EQ:
			ret = p.values(0) == value;
			break;
		case draiosproto::NOT_EQ:
			ret = p.values(0) != value;
			break;
		case draiosproto::CONTAINS:
			ret = value.find(p.values(0)) != std::string::npos;
			break;
		case draiosproto::NOT_CONTAINS:
			ret = value.find(p.values(0)) == std::string::npos;
			break;
		case draiosproto::STARTS_WITH:
			ret = value.substr(0, p.values(0).size()) == p.values(0);
			break;
		case draiosproto::IN_SET:
			ret = false;
			for(auto v : p.values()) {
				if (v == value) {
					ret = true;
					break;
				}
			}
			break;
		case draiosproto::NOT_IN_SET:
			ret = true;
			for(auto v : p.values()) {
				if (v == value) {
					ret = false;
					break;
				}
			}
			break;
		default:
			throw new sinsp_exception("Cannot evaluated scope_predicate " + p.DebugString());
		}

		return ret;
	};

	uid_t uid = make_pair(congroup->uid().kind(), congroup->uid().id());

	if(visited_groups.find(uid) != visited_groups.end()) {
		// Group already visited, continue the evaluation
		return true;
	}

	//
	// Evaluate current group's fields
	// Remove the successfully evaluated ones
	//
	for(auto i = preds.begin(); i != preds.end();) {
		if(congroup->tags().find(i->key()) != congroup->tags().end()) {
			if(!evaluate(*i, congroup->tags().at(i->key()))) {
				return false;
			} else {
				i = preds.erase(i);
			}
		} else {
			++i;
		}
	}

	//
	// All predicates evalutated successfully,
	// nothing else to do
	//
	if (preds.empty()) return true;

	// Remember we've visited this group
	visited_groups.emplace(uid);

	//
	// Evaluate parents' tags
	//
	for(auto p_uid : congroup->parents()) {
		if(!walk_and_match(m_state[make_pair(p_uid.kind(), p_uid.id())].get(), preds, visited_groups)) {
			// A predicate in the upper levels returned false
			// The final result is false
			return false;
		}
		if (preds.empty()) break;
	}

	return true;
}

bool infrastructure_state::match(std::string &container_id, const google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &scope_predicates)
{
	auto pos = m_state.find(make_pair("container", container_id));
	if (pos == m_state.end())
		return false;

	google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> preds(scope_predicates);
	std::unordered_set<uid_t, std::hash<uid_t>> visited;

	return walk_and_match(pos->second.get(), preds, visited) && preds.empty();
}


void infrastructure_state::state_of(const draiosproto::container_group *grp,
				     std::vector<std::unique_ptr<draiosproto::container_group>>& state,
				     std::unordered_set<uid_t>& visited)
{
	uid_t uid = make_pair(grp->uid().kind(), grp->uid().id());

	if(visited.find(uid) != visited.end()) {
		// Group already visited, skip it
		return;
	}
	visited.emplace(uid);


	for (const auto &p_uid : grp->parents()) {
		auto parent = m_state[make_pair(p_uid.kind(), p_uid.id())].get();
		//
		// Build parent state
		//
		state_of(parent, state, visited);
	}

	//
	// Except for containers, add the current node
	//
	if(grp->uid().kind() != "container") {
		auto x = make_unique<draiosproto::container_group>();
		x->CopyFrom(*grp);
		state.emplace_back(std::move(x));
	}
}

void infrastructure_state::state_of(const std::vector<std::string> &container_ids,
				     std::vector<std::unique_ptr<draiosproto::container_group>>& state)
{
	std::unordered_set<uid_t, std::hash<uid_t>> inserted;

	//
	// Retrieve the state of every container
	//
	for(const auto &c_id : container_ids) {
		auto pos = m_state.find(make_pair("container", c_id));
		if (pos == m_state.end()) {
			//
			// This container is not in the orchestrator state
			//
			continue;
		}

		state_of(pos->second.get(), state, inserted);
	}

	//
	// Clean up the broken links
	// (except for container links, that are used to identify the containers)
	//
	for(const auto &state_cgroup : state) {
		for(auto i = state_cgroup->mutable_children()->begin(); i != state_cgroup->mutable_children()->end();) {
			if(i->kind() != "container" &&
			   inserted.find(make_pair(i->kind(), i->id())) == inserted.end()) {
				i = state_cgroup->mutable_children()->erase(i);
			} else {
				++i;
			}
		}
	}
}

void infrastructure_state::debug_print()
{
	glogf(sinsp_logger::SEV_DEBUG, "INFRASTRUCTURE STATE (size: %d)", m_state.size());

	for (auto it = m_state.begin(), e = m_state.end(); it != e; ++it) {
		draiosproto::container_group *cong = it->second.get();
		glogf(sinsp_logger::SEV_DEBUG, " Container group <%s,%s>", cong->uid().kind().c_str(), cong->uid().id().c_str());
		glogf(sinsp_logger::SEV_DEBUG, "  Tags:");
		for (auto t: cong->tags())
			glogf(sinsp_logger::SEV_DEBUG, "   %s:%s", t.first.c_str(), t.second.c_str());
		glogf(sinsp_logger::SEV_DEBUG, "  IP Addresses:");
		for (auto i: cong->ip_addresses())
			glogf(sinsp_logger::SEV_DEBUG, "   %s", i.c_str());
		glogf(sinsp_logger::SEV_DEBUG, "  Ports:");
		for (auto p: cong->ports())
			glogf(sinsp_logger::SEV_DEBUG, "   %d:%s (target:%d, node:%d, published:%d)",
				  p.port(), p.protocol().c_str(), p.target_port(), p.node_port(), p.published_port());
		glogf(sinsp_logger::SEV_DEBUG, "  Metrics:");
		for (auto m: cong->metrics())
			glogf(sinsp_logger::SEV_DEBUG, "   %s:%d", m.first.c_str(), m.second);
		glogf(sinsp_logger::SEV_DEBUG, "  Parents:");
		for (auto m: cong->parents())
			glogf(sinsp_logger::SEV_DEBUG, "   <%s,%s>", m.kind().c_str(), m.id().c_str());
		glogf(sinsp_logger::SEV_DEBUG, "  Children:");
		for (auto m: cong->children())
			glogf(sinsp_logger::SEV_DEBUG, "   <%s,%s>", m.kind().c_str(), m.id().c_str());
	}
}













