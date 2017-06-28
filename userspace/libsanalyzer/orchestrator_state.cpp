#include <algorithm>

#include "orchestrator_state.h"

orchestrator_state::orchestrator_state(uint64_t refresh_interval) :
	m_interval(refresh_interval)
{
	m_callback = [this] (bool successful, google::protobuf::Message *response_msg) {
		sdc_internal::congroup_update_event *evt = (sdc_internal::congroup_update_event *)response_msg;

		google::protobuf::TextFormat::Printer printer; std::string tmp; printer.PrintToString(*evt, &tmp);
		glogf(sinsp_logger::SEV_DEBUG, "[%s] Received update_event message, size %d", successful?"true":"false", evt->ByteSize());
		glogf(sinsp_logger::SEV_DEBUG, "update_event message: %s", tmp.c_str());

		// XXX/mattpag make sure this happens only because the server isn't ready yet
		if (evt->ByteSize() > 0) {
			handle_event(evt);
		}
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
			m_state[key]->CopyFrom(evt->object());
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

	for (auto x : m_state[key]->parents()) {
		auto pkey = make_pair(x.kind(), x.id());
		auto pos = m_state[pkey]->children().begin();

		for (; pos != m_state[pkey]->children().end(); ++pos) {
			if (pos->kind() == evt->object().uid().kind() &&
				pos->id() == evt->object().uid().id()) {
				m_state[pkey]->mutable_children()->erase(pos);
				break;
			}
		}
		if (pos == m_state[pkey]->children().end()) {
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
			m_state.erase(make_pair(x.kind(), x.id()));
		}
	}

	// Remove the group itself
	m_state.erase(key);
}















