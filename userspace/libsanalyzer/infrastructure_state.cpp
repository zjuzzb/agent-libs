#include <algorithm>

#include "infrastructure_state.h"

bool get_cached_result(infrastructure_state::policy_cache_t &cache, std::string &id, uint64_t policy_id, bool *res)
{
	auto cached_results = cache.find(id);
	if(cached_results != cache.end()) {
		auto cached_result = cached_results->second.find(policy_id);
		if (cached_result != cached_results->second.end()) {
			glogf(sinsp_logger::SEV_DEBUG, "Found cached result for id %s, policy id %llu --> %s", id.c_str(), policy_id, res?"true":"false");
			*res = cached_result->second;
			return true;
		}
	}

	//glogf(sinsp_logger::SEV_DEBUG, "Cannot find cached result for id %s, policy id %llu", id.c_str(), policy_id);

	return false;
}

void insert_cached_result(infrastructure_state::policy_cache_t &cache, std::string &id, uint64_t policy_id, bool res)
{
	if(cache.find(id) == cache.end()) {
		cache.emplace(id, std::unordered_map<uint64_t, bool>());
	}

	cache[id].emplace(policy_id, res);

	//glogf(sinsp_logger::SEV_DEBUG, "Cache result (%s) for id %s, policy id %llu", res?"true":"false", id.c_str(), policy_id);
}

bool evaluate_on(draiosproto::container_group *congroup, google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &preds)
{
	auto evaluate = [](draiosproto::scope_predicate p, const std::string &value)
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

infrastructure_state::infrastructure_state(const string& k8s_url, uint64_t refresh_interval) :
	m_interval(refresh_interval),
	m_k8s_url(k8s_url)
{
	m_callback = [this] (bool successful, google::protobuf::Message *response_msg) {

		if(successful) {
			draiosproto::congroup_update_event *evt = (draiosproto::congroup_update_event *)response_msg;
			handle_event(evt);
		} else {
			//
			// Error from cointerface, destroy the whole state and subscribe again
			//
			glogf(sinsp_logger::SEV_WARNING, "Error while receiving orchestrator events. Reset and retry.");
			reset();
		}
	};

	reset();
}

infrastructure_state::~infrastructure_state(){}

void infrastructure_state::refresh(uint64_t ts)
{
	m_interval.run([this]()
	{
		m_coclient.next();
	}, ts);
}

// TODO: handle better various orchestartors
void infrastructure_state::reset()
{
	m_container_p_cache.clear();
	m_host_p_cache.clear();
	m_orphans.clear();
	m_state.clear();

	glogf(sinsp_logger::SEV_DEBUG, "Subscribe to orchestrator events.");
	sdc_internal::orchestrator_events_stream_command cmd;
	cmd.set_url(m_k8s_url);
	m_coclient.get_orchestrator_events(cmd, m_callback);
}

void infrastructure_state::load_single_event(const draiosproto::congroup_update_event &evt)
{
	handle_event(&evt);
}

unsigned int infrastructure_state::size()
{
	return m_state.size();
}

bool infrastructure_state::has(uid_t uid)
{
	return m_state.find(uid) != m_state.end();
}

std::unique_ptr<draiosproto::container_group> infrastructure_state::get(uid_t uid)
{
	if(!has(uid)) {
		return nullptr;
	}

	auto res = make_unique<draiosproto::container_group>();
	res->CopyFrom(*m_state[uid]);

	return res;
}

void infrastructure_state::handle_event(const draiosproto::congroup_update_event *evt)
{
	std::string kind = evt->object().uid().kind();
	std::string id = evt->object().uid().id();

	glogf(sinsp_logger::SEV_DEBUG, "Handling %s event with uid <%s,%s>", draiosproto::congroup_event_type_Name(evt->type()).c_str(), kind.c_str(), id.c_str());

	auto key = make_pair(kind, id);

	if(!has(key)) {
		switch(evt->type()) {
		case draiosproto::ADDED:
			m_state[key] = make_unique<draiosproto::container_group>();
			m_state[key]->CopyFrom(evt->object());
			connect(key);
			break;
		case draiosproto::REMOVED:
			// allow double delete (example: remove a container for an already terminated k8s_job)
			glogf(sinsp_logger::SEV_DEBUG, "Ignoring request to delete non-existent container group <%s,%s>", kind.c_str(), id.c_str());
			break;
		case draiosproto::UPDATED:
			throw new sinsp_exception("Cannot update container_group with id " + id + " because it does not exists.");
			break;
		}
	} else {
		switch(evt->type()) {
		case draiosproto::ADDED:
			throw new sinsp_exception("Cannot add container_group with id " + id + " because it's already present.");
			break;
		case draiosproto::REMOVED:
			remove(evt);
			break;
		case draiosproto::UPDATED:
			glogf(sinsp_logger::SEV_DEBUG, "Current container_group: %s", m_state[key]->DebugString().c_str());
			*m_state[key]->mutable_tags() = evt->object().tags();
			m_state[key]->mutable_ip_addresses()->CopyFrom(evt->object().ip_addresses());
			m_state[key]->mutable_ports()->CopyFrom(evt->object().ports());
			*m_state[key]->mutable_metrics() = evt->object().metrics();
			break;
		}
	}

	glogf(sinsp_logger::SEV_DEBUG, "%s event with uid <%s,%s> handled. Current state size: %d", draiosproto::congroup_event_type_Name(evt->type()).c_str(), kind.c_str(), id.c_str(), m_state.size());
	debug_print();
}

void infrastructure_state::connect(infrastructure_state::uid_t& key)
{
	//
	// Connect the new group to his parents
	//
	for (const auto &x : m_state[key]->parents()) {
		auto pkey = make_pair(x.kind(), x.id());
		if(!has(pkey)) {
			// keep track of the missing parent. We will fix the children links when this event arrives
			if(m_orphans.find(pkey) == m_orphans.end())
				m_orphans[pkey] = std::vector<uid_t>();
			m_orphans[pkey].emplace_back(key.first, key.second);
		} else {
			draiosproto::congroup_uid *child = m_state[pkey]->mutable_children()->Add();
			child->set_kind(key.first);
			child->set_id(key.second);
			glogf(sinsp_logger::SEV_DEBUG, "child <%s,%s> added to <%s,%s>",
				  key.first.c_str(), key.second.c_str(), pkey.first.c_str(), pkey.second.c_str());
		}
	}

	//
	// and connect his children to him
	//
	for (const auto &x : m_state[key]->children()) {
		auto ckey = make_pair(x.kind(), x.id());
		if(!has(ckey)) {
			// the connection will be created when the child arrives
			continue;
		}
		draiosproto::congroup_uid *parent = m_state[ckey]->mutable_parents()->Add();
		parent->set_kind(key.first);
		parent->set_id(key.second);
		glogf(sinsp_logger::SEV_DEBUG, "parent <%s,%s> added to <%s,%s>",
			  key.first.c_str(), key.second.c_str(), ckey.first.c_str(), ckey.second.c_str());
	}

	// Fix any broken link involving this container group
	// do this after checking the children otherwise this node will be added as parent twice
	if(m_orphans.find(key) != m_orphans.end()) {
		for(const auto &orphan_uid : m_orphans[key]) {
			draiosproto::congroup_uid *child = m_state[key]->mutable_children()->Add();
			child->set_kind(orphan_uid.first);
			child->set_id(orphan_uid.second);
			glogf(sinsp_logger::SEV_DEBUG, "(deferred) child <%s,%s> added to <%s,%s>",
				  orphan_uid.first.c_str(), orphan_uid.second.c_str(), key.first.c_str(), key.second.c_str());
		}
		m_orphans.erase(key);
	}
}

void infrastructure_state::remove(const draiosproto::congroup_update_event *evt)
{
	//
	// Remove all children references to this group
	//
	auto key = make_pair(evt->object().uid().kind(), evt->object().uid().id());
	glogf(sinsp_logger::SEV_DEBUG, "Remove container group <%s,%s>", key.first.c_str(), key.second.c_str());

	glogf(sinsp_logger::SEV_DEBUG, "Container group <%s,%s> has %d parents", key.first.c_str(), key.second.c_str(), m_state[key]->parents().size());
	for (const auto &x : m_state[key]->parents()) {
		auto pkey = make_pair(x.kind(), x.id());

		if(!has(pkey)) {
			// parent has already been deleted
			glogf(sinsp_logger::SEV_DEBUG, "Container group <%s,%s> has been already deleted", pkey.first.c_str(), pkey.second.c_str());
			continue;
		}

		bool erased = false;
		glogf(sinsp_logger::SEV_DEBUG, "Searching children links inside container group <%s,%s>", pkey.first.c_str(), pkey.second.c_str());

		for (auto pos = m_state[pkey]->children().begin(); pos != m_state[pkey]->children().end();) {
			if (pos->kind() == evt->object().uid().kind() && pos->id() == evt->object().uid().id()) {
				glogf(sinsp_logger::SEV_DEBUG, "Erase child link from <%s,%s>", pkey.first.c_str(), pkey.second.c_str());
				m_state[pkey]->mutable_children()->erase(pos);
				glogf(sinsp_logger::SEV_DEBUG, "Child link erased.");
				erased = true;
				break;
			} else {
				++pos;
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

	if (m_state[key]->uid().kind() == "container") {
		//
		// Delete all cached results for this container
		//
		m_container_p_cache.erase(m_state[key]->uid().id());
	}

	// Remove the group itself
	m_state.erase(key);

	glogf(sinsp_logger::SEV_DEBUG, "Container group <%s,%s> removed.", key.first.c_str(), key.second.c_str());
}

bool infrastructure_state::walk_and_match(draiosproto::container_group *congroup,
										google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> &preds,
										std::unordered_set<uid_t> &visited_groups)
{
	uid_t uid = make_pair(congroup->uid().kind(), congroup->uid().id());

	if(visited_groups.find(uid) != visited_groups.end()) {
		// Group already visited, continue the evaluation
		return true;
	}

	//
	// Evaluate current group's fields
	// Remove the successfully evaluated ones
	//
	if(!evaluate_on(congroup, preds)) {
		// A predicate is false
		return false;
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
	for(const auto &p_uid : congroup->parents()) {

		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if(!has(pkey)) {
			// We don't have this parent (yet...)
			glogf(sinsp_logger::SEV_WARNING, "Warning, cannot fully evaluate policy scope because the infrastructure state is incomplete.");
			return false;
		}

		if(!walk_and_match(m_state[pkey].get(), preds, visited_groups)) {
			// A predicate in the upper levels returned false
			// The final result is false
			return false;
		}
		if (preds.empty()) break;
	}

	return true;
}

bool infrastructure_state::match_scope(std::string &container_id, std::string &host_id, const draiosproto::policy &policy)
{
	// glogf(sinsp_logger::SEV_DEBUG, "Match policy scope with c_id: \"%s\", h_id: \"%s\", p_id: %llu, container_scope: %s, host_scope: %s",
	// 	container_id.c_str(), host_id.c_str(), policy.id(), policy.container_scope()?"true":"false", policy.host_scope()?"true":"false");

	bool result;
	uid_t uid;

	if((container_id.empty() && !policy.host_scope()) ||
		(!container_id.empty() && !policy.container_scope())) {
		// the policy isn't meant to be applied to this event
		return false;
	}

	if (!container_id.empty() && policy.container_scope()) {
		uid = make_pair("container", container_id);
	} else {
		uid = make_pair("host", host_id);
	}

	policy_cache_t &cache = uid.first == "host" ? m_host_p_cache : m_container_p_cache;

	if(policy.scope_predicates().empty()) {
		// no predicates, we can safely return true immediately
		result = true;
	} else {

		if(get_cached_result(cache, uid.second, policy.id(), &result)) {
			return result;
		}

		auto pos = m_state.find(uid);
		if (pos == m_state.end())
			return false;

		google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> preds(policy.scope_predicates());

		if (uid.first == "host") {
			result = evaluate_on(pos->second.get(), preds);
		} else {
			std::unordered_set<uid_t, std::hash<uid_t>> visited;
			result = walk_and_match(pos->second.get(), preds, visited);
		}
	}

	insert_cached_result(cache, uid.second, policy.id(), result);

	return result;
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
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if(!has(pkey)) {
			// We don't have this parent (yet...)
			continue;
		}

		//
		// Build parent state
		//
		state_of(m_state[pkey].get(), state, visited);
	}

	//
	// Except for containers and hosts, add the current node
	//
	if(grp->uid().kind() != "container" && grp->uid().kind() != "host") {
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

void infrastructure_state::refresh_host_metadata(const google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event> &host_events)
{
	//
	// Remove current hosts
	//
	for (auto i = m_state.begin(); i != m_state.end();) {
		auto congroup = i->second.get();
		// remove all the links to host nodes
		if(host_children.find(congroup->uid().kind()) != host_children.end()) {
			for(auto j = congroup->children().begin(), j_end = congroup->children().end(); j != j_end; ++j) {
				if(j->kind() == "host") {
					congroup->mutable_children()->erase(j);
					break;
				}
			}
		}

		if(congroup->uid().kind() == "host") {
			i = m_state.erase(i);
		} else {
			++i;
		}
	}

	//
	// Delete all cached results for host scope policies
	//
	m_host_p_cache.clear();

	glogf(sinsp_logger::SEV_INFO, "Adding %d hosts to infrastructure state", host_events.size());

	//
	// Connect the refreshed data to the state
	//
	for(auto hevt : host_events) {

		auto host = hevt.mutable_object();

		glogf(sinsp_logger::SEV_DEBUG, "Add host %s to infrastructure state", host->uid().id().c_str());
		uid_t child_uid;
		std::vector<uid_t> nodes;

		for (auto i = m_state.begin(), e = m_state.end(); i != e; ++i) {
			auto congroup = i->second.get();
			if (host_children.find(congroup->uid().kind()) != host_children.end()) {
				for (auto j = congroup->ip_addresses().begin(), j_end = congroup->ip_addresses().end(); j != j_end; ++j) {
					for(auto k = host->ip_addresses().begin(), k_end = host->ip_addresses().end(); k != k_end; ++k) {
						if(*j == *k) {
							nodes.emplace_back(congroup->uid().kind(), congroup->uid().id());
						}
					}
				}
			}
		}

		if (nodes.empty()) {
			// this could also happen if the node has been removed but the backend didn't realized it yet
			glogf(sinsp_logger::SEV_WARNING, "Cannot match host %s, no suitable orchestrator nodes found.", host->uid().id().c_str());
			continue;
		} else if(nodes.size() == 1) {
			child_uid = *nodes.begin();
		} else {
			glogf(sinsp_logger::SEV_WARNING, "Multiple matches while inserting metadata of host %s inside the infrastructure state", host->uid().id().c_str());

			//
			// Tiebreak based on hostName
			//
			bool found = false;
			if(host->tags().find("host.hostName") != host->tags().end()) {
				for(const auto c_uid : nodes) {
					if(m_state[c_uid]->tags().find(c_uid.first + ".name") != m_state[c_uid]->tags().end()) {
						std::string h_hn = m_state[c_uid]->tags().at(c_uid.first + ".name");
						std::string n_hn = host->tags().at("host.hostName");
						std::transform(h_hn.begin(), h_hn.end(), h_hn.begin(), ::tolower);
						std::transform(n_hn.begin(), n_hn.end(), n_hn.begin(), ::tolower);
						if (h_hn == n_hn) {
							found = true;
							child_uid = c_uid;
							break;
						}
					}
				}
			}

			if (!found) {
				glogf(sinsp_logger::SEV_WARNING, "Matching host %s when multiple agents matched based on IP but none matched on hostname", host->uid().id().c_str());
				child_uid = *nodes.begin();
			}
		}

		//
		// Add the children link, handle_event will take care of connecting the host to the state
		//
		draiosproto::congroup_uid *c = host->mutable_children()->Add();
		c->set_kind(child_uid.first);
		c->set_id(child_uid.second);

		handle_event(&hevt);
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