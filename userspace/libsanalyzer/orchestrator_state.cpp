#include <algorithm>

#include "orchestrator_state.h"

orchestrator_state::orchestrator_state(uint64_t refresh_interval) :
	m_interval(refresh_interval)
{
	m_callback = [this] (bool successful, google::protobuf::Message *response_msg) {
		sdc_internal::congroup_update_event *evt = (sdc_internal::congroup_update_event *)response_msg;

		//google::protobuf::TextFormat::Printer printer; std::string tmp; printer.PrintToString(*evt, &tmp);
		//glogf(sinsp_logger::SEV_DEBUG, "[%s] Received update_event message, size %d", successful?"true":"false", evt->ByteSize());
		//glogf(sinsp_logger::SEV_DEBUG, "update_event message: %s", tmp.c_str());

		handle_event(evt);
		debug_print();
	};

	glogf(sinsp_logger::SEV_DEBUG, "Sending Request for orchestrator events.");
	m_coclient.get_orchestrator_events(m_callback);
}

orchestrator_state::~orchestrator_state(){}

void orchestrator_state::refresh()
{
	m_interval.run([this]()
	{
		m_coclient.next();
	});
}

void orchestrator_state::handle_event(sdc_internal::congroup_update_event *evt)
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

void orchestrator_state::connect(orchestrator_state::uid_t& key)
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

void orchestrator_state::remove(sdc_internal::congroup_update_event *evt)
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

bool orchestrator_state::walk_and_match(draiosproto::container_group *congroup,
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
			ret = p.values(0).find(value) != std::string::npos;
			break;
		case draiosproto::NOT_CONTAINS:
			ret = p.values(0).find(value) == std::string::npos;
			break;
		case draiosproto::STARTS_WITH:
			ret = p.values(0).substr(0, value.size()) == value;
			break;
		case draiosproto::IN_SET:
			ret = false;
			for(auto v : p.values()) {
				if (v == value)
					ret = true;
				break;
			}
			break;
		case draiosproto::NOT_IN_SET:
			ret = true;
			for(auto v : p.values()) {
				if (v == value)
					ret = false;
				break;
			}
			break;
		default:
			throw new sinsp_exception("Cannot evaluated scope_predicate " + p.DebugString());
		}

		return ret;
	};

	uid_t uid = make_pair(congroup->uid().kind(), congroup->uid().id());
	if(visited_groups.find(uid) != visited_groups.end()) {
		// Groups already visited, continue the evaluation
		return true;
	}

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

	return true;
}

bool orchestrator_state::match(std::string &container_id, const google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &scope_predicates)
{
	auto pos = m_state.find(make_pair("container", container_id));
	if (pos == m_state.end())
		return false;

	google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> preds(scope_predicates);
	std::unordered_set<uid_t, std::hash<uid_t>> visited;

	return walk_and_match(pos->second.get(), preds, visited) && preds.empty();
}

void orchestrator_state::debug_print()
{
	glogf(sinsp_logger::SEV_DEBUG, "ORCHESTRATOR STATE (size: %d)", m_state.size());

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













