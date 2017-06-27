#include "orchestrator_state.h"

orchestrator_state::orchestrator_state(uint64_t refresh_interval) :
	m_interval(refresh_interval)
{
	m_callback = [this] (bool successful, google::protobuf::Message *response_msg) {
		sdc_internal::congroup_update_event *evt = (sdc_internal::congroup_update_event *)response_msg;

		google::protobuf::TextFormat::Printer printer; std::string tmp; printer.PrintToString(*evt, &tmp);
		g_logger.format(sinsp_logger::SEV_DEBUG, "[%s] Received update_event message, size %d", successful?"true":"false", evt->ByteSize());
		g_logger.format(sinsp_logger::SEV_DEBUG, "update_event message: %s", tmp.c_str());

		// XXX/mattpag make sure this happens only because the server isn't ready yet
		if (evt->ByteSize() > 0) {
			handle_event(evt);
		}
	};

	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending Request for orchestrator events.");
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

	g_logger.format(sinsp_logger::SEV_DEBUG, "Handling event with uid <%s,%s>", kind.c_str(), id.c_str());

	auto key = make_pair(kind, id);

	bool is_present = m_state.find(key) != m_state.end();
	if(!is_present) {
		switch(evt->type()) {
		case sdc_internal::ADDED:
			m_state[key] = make_shared<draiosproto::container_group>();
			m_state[key]->CopyFrom(evt->object());
			break;
		case sdc_internal::REMOVED:
			throw new sinsp_exception("Cannot remove container_group with id " + id + " because it was never here.");
			break;
		case sdc_internal::UPDATED:
			throw new sinsp_exception("Cannot update container_group with id " + id + " because it was never here.");
			break;
		}
	} else {
		switch(evt->type()) {
		case sdc_internal::ADDED:
			throw new sinsp_exception("Cannot add container_group with id " + id + " because it's already present.");
			break;
		case sdc_internal::REMOVED:
			break;
		case sdc_internal::UPDATED:
			break;
		}
	}

	g_logger.format(sinsp_logger::SEV_DEBUG, "Event with uid <%s,%s> handled. Current state size: %d", kind.c_str(), id.c_str(), m_state.size());

}
